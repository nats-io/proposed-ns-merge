// Copyright 2023 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/s2"
	"golang.org/x/crypto/ocsp"

	"github.com/nats-io/nats-server/v2/server/certidp"
)

const (
	OCSPResponseCacheDefaultDir            = "_rc_"
	OCSPResponseCacheDefaultFilename       = "cache.json"
	OCSPResponseCacheDefaultTempFilePrefix = "ocsprc-*"
)

type OCSPResponseCacheType int

const (
	NONE OCSPResponseCacheType = iota + 1
	LOCAL
)

var OCSPResponseCacheTypeMap = map[string]OCSPResponseCacheType{
	"none":  NONE,
	"local": LOCAL,
}

type OCSPResponseCacheConfig struct {
	Type            OCSPResponseCacheType
	LocalStore      string
	PreserveRevoked bool
}

type OCSPResponseCacheStats struct {
	Responses int64 `json:"size"`
	Hits      int64 `json:"hits"`
	Misses    int64 `json:"misses"`
	Revokes   int64 `json:"revokes"`
	Goods     int64 `json:"goods"`
	Unknowns  int64 `json:"unknowns"`
}

type OCSPResponseCacheItem struct {
	Subject     string                  `json:"subject,omitempty"`
	CachedAt    time.Time               `json:"cached_at"`
	RespStatus  certidp.StatusAssertion `json:"resp_status"`
	RespExpires time.Time               `json:"resp_expires,omitempty"`
	Resp        []byte                  `json:"resp"`
}

type OCSPResponseCache interface {
	Put(key string, resp *ocsp.Response, subj string, log *certidp.Log)
	Get(key string, log *certidp.Log) []byte
	Delete(key string, miss bool, log *certidp.Log)
	Type() string
	Start(s *Server)
	Stop(s *Server)
	Online() bool
	Config() *OCSPResponseCacheConfig
	Stats() *OCSPResponseCacheStats
}

// NoOpCache is a no-op implementation of OCSPResponseCache
type NoOpCache struct {
	config *OCSPResponseCacheConfig
	stats  *OCSPResponseCacheStats
	online bool
}

func (c *NoOpCache) Put(_ string, _ *ocsp.Response, _ string, _ *certidp.Log) {
	return
}

func (c *NoOpCache) Get(_ string, _ *certidp.Log) []byte {
	return nil
}

func (c *NoOpCache) Delete(_ string, _ bool, _ *certidp.Log) {
	return
}

func (c *NoOpCache) Start(_ *Server) {
	c.stats = &OCSPResponseCacheStats{}
	c.online = true
	return
}

func (c *NoOpCache) Stop(_ *Server) {
	c.online = false
	return
}

func (c *NoOpCache) Online() bool {
	return c.online
}

func (c *NoOpCache) Type() string {
	return "none"
}

func (c *NoOpCache) Config() *OCSPResponseCacheConfig {
	return c.config
}

func (c *NoOpCache) Stats() *OCSPResponseCacheStats {
	return c.stats
}

// LocalCache is a local file implementation of OCSPResponseCache
type LocalCache struct {
	config *OCSPResponseCacheConfig
	stats  *OCSPResponseCacheStats
	online bool
	cache  map[string]OCSPResponseCacheItem
	mux    *sync.RWMutex
}

// Put captures a CA OCSP response to the OCSP peer cache indexed by response fingerprint (a hash)
func (c *LocalCache) Put(key string, caResp *ocsp.Response, subj string, log *certidp.Log) {
	if !c.online || caResp == nil || key == "" {
		return
	}
	log.Debugf(certidp.DbgCachingResponse, subj, key)
	rawC, err := c.Compress(caResp.Raw)
	if err != nil {
		log.Errorf(certidp.ErrResponseCompressFail, key, err)
		return
	}
	log.Debugf(certidp.DbgAchievedCompression, float64(len(rawC))/float64(len(caResp.Raw)))
	c.mux.Lock()
	defer c.mux.Unlock()
	// check if we are replacing and do stats
	item, ok := c.cache[key]
	if ok {
		c.adjustStats(-1, item.RespStatus)
	}
	item = OCSPResponseCacheItem{
		Subject:     subj,
		CachedAt:    time.Now().UTC().Round(time.Second),
		RespStatus:  certidp.StatusAssertionIntToVal[caResp.Status],
		RespExpires: caResp.NextUpdate,
		Resp:        rawC,
	}
	c.cache[key] = item
	c.adjustStats(1, item.RespStatus)
}

// Get returns a CA OCSP response from the OCSP peer cache matching the response fingerprint (a hash)
func (c *LocalCache) Get(key string, log *certidp.Log) []byte {
	if !c.online || key == "" {
		return nil
	}
	c.mux.RLock()
	defer c.mux.RUnlock()
	val, ok := c.cache[key]
	if ok {
		atomic.AddInt64(&c.stats.Hits, 1)
		log.Debugf(certidp.DbgCacheHit, key)
	} else {
		atomic.AddInt64(&c.stats.Misses, 1)
		log.Debugf(certidp.DbgCacheMiss, key)
		return nil
	}
	resp, err := c.Decompress(val.Resp)
	if err != nil {
		log.Errorf(certidp.ErrResponseDecompressFail, key, err)
		return nil
	}
	return resp
}

func (c *LocalCache) adjustStatsHitToMiss() {
	atomic.AddInt64(&c.stats.Misses, 1)
	atomic.AddInt64(&c.stats.Hits, -1)
}

func (c *LocalCache) adjustStats(delta int64, rs certidp.StatusAssertion) {
	if delta == 0 {
		return
	}
	atomic.AddInt64(&c.stats.Responses, delta)
	switch rs {
	case ocsp.Good:
		atomic.AddInt64(&c.stats.Goods, delta)
	case ocsp.Revoked:
		atomic.AddInt64(&c.stats.Revokes, delta)
	case ocsp.Unknown:
		atomic.AddInt64(&c.stats.Unknowns, delta)
	}
}

// Delete removes a CA OCSP response from the OCSP peer cache matching the response fingerprint (a hash)
func (c *LocalCache) Delete(key string, wasMiss bool, log *certidp.Log) {
	if !c.online || key == "" || c.config == nil {
		return
	}
	c.mux.Lock()
	defer c.mux.Unlock()
	item, ok := c.cache[key]
	if !ok {
		return
	}
	if item.RespStatus == ocsp.Revoked && c.config.PreserveRevoked {
		log.Debugf(certidp.DbgPreservedRevocation, key)
		if wasMiss {
			c.adjustStatsHitToMiss()
		}
		return
	}
	log.Debugf(certidp.DbgDeletingCacheResponse, key)
	delete(c.cache, key)
	c.adjustStats(-1, item.RespStatus)
	if wasMiss {
		c.adjustStatsHitToMiss()
	}
}

// Start initializes the configured OCSP peer cache, loads a saved cache from disk (if present), and initializes runtime statistics
func (c *LocalCache) Start(s *Server) {
	s.Debugf(certidp.DbgStartingCache)
	c.loadCache(s)
	c.initStats()
	c.online = true
	return
}

func (c *LocalCache) Stop(s *Server) {
	s.Debugf(certidp.DbgStoppingCache)
	c.online = false
	c.saveCache(s)
	return
}

func (c *LocalCache) Online() bool {
	return c.online
}

func (c *LocalCache) Type() string {
	return "local"
}

func (c *LocalCache) Config() *OCSPResponseCacheConfig {
	return c.config
}

func (c *LocalCache) Stats() *OCSPResponseCacheStats {
	if c.stats == nil {
		return nil
	}
	c.mux.RLock()
	stats := OCSPResponseCacheStats{
		Responses: c.stats.Responses,
		Hits:      c.stats.Hits,
		Misses:    c.stats.Misses,
		Revokes:   c.stats.Revokes,
		Goods:     c.stats.Goods,
		Unknowns:  c.stats.Unknowns,
	}
	c.mux.RUnlock()
	return &stats
}

func (c *LocalCache) initStats() {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.stats = &OCSPResponseCacheStats{}
	c.stats.Hits = 0
	c.stats.Misses = 0
	c.stats.Responses = int64(len(c.cache))
	for _, resp := range c.cache {
		switch resp.RespStatus {
		case ocsp.Good:
			c.stats.Goods++
		case ocsp.Revoked:
			c.stats.Revokes++
		case ocsp.Unknown:
			c.stats.Unknowns++
		}
	}
}

func (c *LocalCache) Compress(buf []byte) ([]byte, error) {
	bodyLen := int64(len(buf))
	var output bytes.Buffer
	var writer io.WriteCloser
	writer = s2.NewWriter(&output)
	input := bytes.NewReader(buf[:bodyLen])
	if n, err := io.CopyN(writer, input, bodyLen); err != nil {
		return nil, fmt.Errorf(certidp.ErrCannotWriteCompressed, err)
	} else if n != bodyLen {
		return nil, fmt.Errorf(certidp.ErrTruncatedWrite, n, bodyLen)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf(certidp.ErrCannotCloseWriter, err)
	}
	return output.Bytes(), nil
}

func (c *LocalCache) Decompress(buf []byte) ([]byte, error) {
	bodyLen := int64(len(buf))
	input := bytes.NewReader(buf[:bodyLen])
	var reader io.ReadCloser
	reader = io.NopCloser(s2.NewReader(input))
	output, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf(certidp.ErrCannotReadCompressed, err)
	}
	return output, reader.Close()
}

func (c *LocalCache) loadCache(s *Server) {
	d := s.opts.OCSPCacheConfig.LocalStore
	if d == _EMPTY_ {
		d = OCSPResponseCacheDefaultDir
	}
	f := OCSPResponseCacheDefaultFilename
	store, err := filepath.Abs(path.Join(d, f))
	if err != nil {
		s.Errorf(certidp.ErrLoadCacheFail, err)
		return
	}
	s.Debugf(certidp.DbgLoadingCache, store)
	c.mux.Lock()
	defer c.mux.Unlock()
	c.cache = make(map[string]OCSPResponseCacheItem)
	dat, err := os.ReadFile(store)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.Debugf(certidp.DbgNoCacheFound)
		} else {
			s.Warnf(certidp.ErrLoadCacheFail, err)
		}
		return
	}
	err = json.Unmarshal(dat, &c.cache)
	if err != nil {
		// make sure clean cache
		c.cache = make(map[string]OCSPResponseCacheItem)
		s.Warnf(certidp.ErrLoadCacheFail, err)
		return
	}
}

func (c *LocalCache) saveCache(s *Server) {
	d := OCSPResponseCacheDefaultDir
	f := OCSPResponseCacheDefaultFilename
	store, err := filepath.Abs(path.Join(d, f))
	if err != nil {
		s.Errorf(certidp.ErrSaveCacheFail, err)
		return
	}
	s.Debugf(certidp.DbgSavingCache, store)
	if _, err := os.Stat(d); os.IsNotExist(err) {
		err = os.Mkdir(d, defaultDirPerms)
		if err != nil {
			s.Errorf(certidp.ErrSaveCacheFail, err)
			return
		}
	}
	tmp, err := os.CreateTemp(d, OCSPResponseCacheDefaultTempFilePrefix)
	if err != nil {
		s.Errorf(certidp.ErrSaveCacheFail, err)
		return
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}() // clean up any temp files
	c.mux.RLock()
	defer c.mux.RUnlock()
	dat, err := json.MarshalIndent(c.cache, "", " ")
	if err != nil {
		s.Errorf(certidp.ErrSaveCacheFail, err)
		return
	}
	cacheSize, err := tmp.Write(dat)
	if err != nil {
		s.Errorf(certidp.ErrSaveCacheFail, err)
		return
	}
	err = tmp.Sync()
	if err != nil {
		s.Errorf(certidp.ErrSaveCacheFail, err)
		return
	}
	err = tmp.Close()
	if err != nil {
		s.Errorf(certidp.ErrSaveCacheFail, err)
		return
	}

	// do the final swap and overwrite any old saved peer cache
	err = os.Rename(tmp.Name(), store)
	if err != nil {
		s.Errorf(certidp.ErrSaveCacheFail, err)
		return
	}
	s.Debugf(certidp.DbgCacheSaved, cacheSize)
}

var _ = `
For client, leaf spoke (remotes), and leaf hub connections, you may enable OCSP peer response cacheing:

	...
	# true defaults to "local" cache type, if false (or ocsp_cache is not defined) and TLS peer verification is configured, type "none" is implied
	ocsp_cache: <true, false>
	-OR-
	ocsp_cache {
	   # Cache OCSP responses for the duration of the CA response validity period
	   type: <none, local>
	   local_store: </path/to/store>
	   preserve_revoked: <true, false>  (default false)
	}
	...

Note: Cache of server's own OCSP response (staple) is enabled using the 'ocsp' option.
`

func (s *Server) initOCSPResponseCache() {
	// No mTLS OCSP or Leaf OCSP enablements, so no need to init cache
	if !s.ocspPeerVerify {
		return
	}
	so := s.getOpts()
	if so.OCSPCacheConfig == nil {
		so.OCSPCacheConfig = &OCSPResponseCacheConfig{
			Type: LOCAL,
		}
	}
	var cc = so.OCSPCacheConfig
	switch cc.Type {
	case NONE:
		s.ocsprc = &NoOpCache{config: cc, online: true}
	case LOCAL:
		s.ocsprc = &LocalCache{
			config: cc,
			online: false,
			cache:  make(map[string]OCSPResponseCacheItem),
			mux:    &sync.RWMutex{},
		}
	default:
		s.Fatalf(certidp.ErrBadCacheTypeConfig, cc.Type)
	}
}

func (s *Server) startOCSPResponseCache() {
	// No mTLS OCSP or Leaf OCSP enablements, so no need to start cache
	if !s.ocspPeerVerify || s.ocsprc == nil {
		return
	}

	// Could be heavier operation depending on cache implementation
	s.ocsprc.Start(s)
	if s.ocsprc.Online() {
		s.Noticef(certidp.MsgCacheOnline, s.ocsprc.Type())
	} else {
		s.Noticef(certidp.MsgCacheOffline, s.ocsprc.Type())
	}
}

func (s *Server) stopOCSPResponseCache() {
	if s.ocsprc == nil {
		return
	}
	s.ocsprc.Stop(s)
}

func parseOCSPResponseCache(v interface{}) (pcfg *OCSPResponseCacheConfig, retError error) {
	var lt token
	defer convertPanicToError(&lt, &retError)
	tk, v := unwrapValue(v, &lt)
	cm, ok := v.(map[string]interface{})
	if !ok {
		return nil, &configErr{tk, fmt.Sprintf(certidp.ErrIllegalCacheOptsConfig, v)}
	}
	pcfg = &OCSPResponseCacheConfig{
		Type: LOCAL,
	}
	retError = nil
	for mk, mv := range cm {
		// Again, unwrap token value if line check is required.
		tk, mv = unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "type":
			cache, ok := mv.(string)
			if !ok {
				return nil, &configErr{tk, fmt.Sprintf(certidp.ErrParsingCacheOptFieldGeneric, mk)}
			}
			cacheType, exists := OCSPResponseCacheTypeMap[strings.ToLower(cache)]
			if !exists {
				return nil, &configErr{tk, fmt.Sprintf(certidp.ErrUnknownCacheType, cache)}
			}
			pcfg.Type = cacheType
		case "local_store":
			store, ok := mv.(string)
			if !ok {
				return nil, &configErr{tk, fmt.Sprintf(certidp.ErrParsingCacheOptFieldGeneric, mk)}
			}
			pcfg.LocalStore = store
		case "preserve_revoked":
			preserve, ok := mv.(bool)
			if !ok {
				return nil, &configErr{tk, fmt.Sprintf(certidp.ErrParsingCacheOptFieldGeneric, mk)}
			}
			pcfg.PreserveRevoked = preserve
		default:
			return nil, &configErr{tk, fmt.Sprintf(certidp.ErrParsingCacheOptFieldGeneric, mk)}
		}
	}
	return pcfg, nil
}
