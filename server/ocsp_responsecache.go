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
	OCSPResponseCacheDefaultDir      = "ocsp_cache"
	OCSPResponseCacheDefaultFilename = "cache.json"
)

type OCSPResponseCacheConfig struct {
	Type certidp.CacheType
}

type OCSPResponseCacheStats struct {
	Items   int64 `json:"size"`
	Hits    int64 `json:"hits"`
	Misses  int64 `json:"misses"`
	Revokes int64 `json:"revokes"`
	Goods   int64 `json:"goods"`
}

type OCSPResponseCacheItem struct {
	CachedAt    time.Time `json:"cached_at"`
	RespStatus  int       `json:"resp_status"`
	RespExpires time.Time `json:"resp_expires,omitempty"`
	Resp        []byte    `json:"resp"`
}

type OCSPResponseCache interface {
	Put(key string, resp *ocsp.Response, log *certidp.Log)
	Get(key string, log *certidp.Log) []byte
	Delete(key string, log *certidp.Log)
	Type() string
	Start(s *Server)
	Stop(s *Server)
	Online() bool
	Config() *OCSPResponseCacheConfig
	Stats() *OCSPResponseCacheStats
}

// NoOpCache is a no-op implementation of OCSPResponseCache for consistent runtime implementation of verification
type NoOpCache struct {
	config *OCSPResponseCacheConfig
	stats  *OCSPResponseCacheStats
	online bool
}

func (c *NoOpCache) Put(_ string, _ *ocsp.Response, _ *certidp.Log) {
	return
}

func (c *NoOpCache) Get(_ string, _ *certidp.Log) []byte {
	return nil
}

func (c *NoOpCache) Delete(_ string, _ *certidp.Log) {
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

// LocalCache is a local persistent implementation of OCSPResponseCache
type LocalCache struct {
	config *OCSPResponseCacheConfig
	stats  *OCSPResponseCacheStats
	online bool
	cache  map[string]OCSPResponseCacheItem
	mux    *sync.RWMutex
}

func (c *LocalCache) Put(key string, caResp *ocsp.Response, log *certidp.Log) {
	if !c.online || caResp == nil || key == "" {
		return
	}
	log.Debugf("Caching OCSP response for key %s", key)
	rawC, err := c.Compress(caResp.Raw)
	if err != nil {
		log.Errorf("Error compressing OCSP response for key %s: %s", key, err)
		return
	}
	log.Debugf("OCSP response compression ratio: %f", float64(len(rawC))/float64(len(caResp.Raw)))
	c.mux.Lock()
	defer c.mux.Unlock()
	item := OCSPResponseCacheItem{
		RespStatus: caResp.Status,
		Resp:       rawC,
	}
	c.cache[key] = item
	c.stats.Items = int64(len(c.cache))
}

func (c *LocalCache) Get(key string, log *certidp.Log) []byte {
	if !c.online || key == "" {
		return nil
	}
	c.mux.RLock()
	defer c.mux.RUnlock()
	val, ok := c.cache[key]
	if ok {
		atomic.AddInt64(&c.stats.Hits, 1)
		log.Debugf("OCSP response cache hit for key %s", key)
	} else {
		atomic.AddInt64(&c.stats.Misses, 1)
		log.Debugf("OCSP response cache miss for key %s", key)
		return nil
	}
	resp, err := c.Decompress(val.Resp)
	if err != nil {
		log.Errorf("Error decompressing OCSP response for key %s: %s", key, err)
		return nil
	}
	return resp
}

func (c *LocalCache) Delete(key string, log *certidp.Log) {
	if !c.online || key == "" {
		return
	}
	log.Debugf("Deleting OCSP response for key %s", key)
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.cache, key)
	c.stats.Items = int64(len(c.cache))
}

func (c *LocalCache) Start(s *Server) {
	s.Debugf("Starting OCSP response cache")
	c.loadCache(s)
	c.stats = &OCSPResponseCacheStats{}
	c.stats.Hits = 0
	c.stats.Misses = 0
	c.stats.Items = int64(len(c.cache))
	c.online = true
	return
}

func (c *LocalCache) Stop(s *Server) {
	s.Debugf("Stopping OCSP response cache")
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
		Items:   c.stats.Items,
		Hits:    c.stats.Hits,
		Misses:  c.stats.Misses,
		Revokes: c.stats.Revokes,
		Goods:   c.stats.Goods,
	}
	c.mux.RUnlock()
	return &stats
}

func (c *LocalCache) Compress(buf []byte) ([]byte, error) {
	bodyLen := int64(len(buf))
	var output bytes.Buffer
	var writer io.WriteCloser
	writer = s2.NewWriter(&output)
	input := bytes.NewReader(buf[:bodyLen])
	if n, err := io.CopyN(writer, input, bodyLen); err != nil {
		return nil, fmt.Errorf("error writing to compression writer: %w", err)
	} else if n != bodyLen {
		return nil, fmt.Errorf("short write on body (%d != %d)", n, bodyLen)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("error closing compression writer: %w", err)
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
		return nil, fmt.Errorf("error reading compression reader: %w", err)
	}
	return output, reader.Close()
}

func (c *LocalCache) loadCache(s *Server) {
	d := OCSPResponseCacheDefaultDir
	f := OCSPResponseCacheDefaultFilename
	store, err := filepath.Abs(path.Join(d, f))
	if err != nil {
		s.Errorf("Unable to load OCSP response cache: %w", err)
		return
	}
	s.Noticef("Loading OCSP response cache [%s]", store)
	c.mux.Lock()
	defer c.mux.Unlock()
	c.cache = make(map[string]OCSPResponseCacheItem)
	dat, err := os.ReadFile(store)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.Noticef("No OCSP response cache found, starting with empty cache")
		} else {
			s.Warnf("Unable to load saved OCSP response cache: %w", err)
		}
		return
	}
	err = json.Unmarshal(dat, &c.cache)
	if err != nil {
		// make sure clean cache
		c.cache = make(map[string]OCSPResponseCacheItem)
		s.Warnf("Unable to load saved OCSP response cache: %w", err)
		return
	}
}

func (c *LocalCache) saveCache(s *Server) {
	d := OCSPResponseCacheDefaultDir
	f := OCSPResponseCacheDefaultFilename
	store, err := filepath.Abs(path.Join(d, f))
	if err != nil {
		s.Errorf("Unable to save OCSP response cache: %w", err)
		return
	}
	s.Noticef("Saving OCSP response cache [%s]", store)
	if _, err := os.Stat(d); os.IsNotExist(err) {
		err = os.Mkdir(d, 0755)
		if err != nil {
			s.Errorf("Unable to save OCSP response cache: %w", err)
			return
		}
	}
	tmp, err := os.CreateTemp(d, "ocsprc-*")
	if err != nil {
		s.Errorf("Unable to save OCSP response cache: %w", err)
		return
	}
	defer os.Remove(tmp.Name())

	c.mux.RLock()
	defer c.mux.RUnlock()
	dat, err := json.MarshalIndent(c.cache, "", " ")
	if err != nil {
		s.Errorf("Unable to save OCSP response cache: %w", err)
		return
	}
	err = os.WriteFile(tmp.Name(), dat, 0644)
	if err != nil {
		s.Errorf("Unable to save OCSP response cache: %w", err)
		return
	}
	err = os.Rename(tmp.Name(), store)
	if err != nil {
		s.Errorf("Unable to save OCSP response cache: %w", err)
		return
	}
}

var _ = `
For client, leaf spoke (remotes), and leaf hub connections, you may enable OCSP response cacheing:

	...
	# true defaults to "local" cache type, if false (or ocsp_cache is not defined) and TLS peer verification is configured, type "none" is implied
	ocsp_cache: <true, false>
	-OR-
	ocsp_cache {
	   # Cache OCSP responses for the duration of the CA response validity period
	   type: <none, local>
	}
	...

Note: Cache of server's own OCSP response (staple) is enabled using the 'ocsp' staple option.
`

func (s *Server) initOCSPResponseCache() {
	// No mTLS OCSP or Leaf OCSP enablements, so no need to init cache
	if !s.ocspPeerVerify {
		return
	}

	so := s.getOpts()
	if so.OCSPCacheConfig == nil {
		so.OCSPCacheConfig = &OCSPResponseCacheConfig{
			Type: certidp.NONE,
		}
	}

	var cc = so.OCSPCacheConfig

	switch cc.Type {
	case certidp.NONE:
		s.ocsprc = &NoOpCache{config: cc, online: true}
	case certidp.LOCAL:
		s.ocsprc = &LocalCache{
			config: cc,
			online: false,
			cache:  make(map[string]OCSPResponseCacheItem),
			mux:    &sync.RWMutex{},
		}
	default:
		s.Fatalf("Unimplemented OCSP response cache type: %v", cc.Type)
	}
}

func (s *Server) startOCSPResponseCache() {
	// No mTLS OCSP or Leaf OCSP enablements, so no need to start cache
	if !s.ocspPeerVerify || s.ocsprc == nil {
		return
	}

	// Starting the cache means different things depending on the selected implementation
	// from no-op to setting up NATS KV Client, and potentially creation of a Bucket
	s.ocsprc.Start(s)

	if s.ocsprc.Online() {
		s.Noticef("OCSP response cache online, type: %s", s.ocsprc.Type())
	} else {
		s.Noticef("OCSP response cache offline, type: %s", s.ocsprc.Type())
	}
}

func (s *Server) stopOCSPResponseCache() {
	if s.ocsprc == nil {
		return
	}
	// Stopping the cache means different things depending on the selected implementation
	s.Noticef("Stopping OCSP response cache...")
	s.ocsprc.Stop(s)
}

func parseOCSPResponseCache(v interface{}) (pcfg *OCSPResponseCacheConfig, retError error) {
	var lt token
	defer convertPanicToError(&lt, &retError)

	tk, v := unwrapValue(v, &lt)
	cm, ok := v.(map[string]interface{})
	if !ok {
		return nil, &configErr{tk, fmt.Sprintf("Expected map to define ocsp response cache opts, got %T", v)}
	}

	pcfg = &OCSPResponseCacheConfig{
		Type: certidp.NONE,
	}

	retError = nil

	for mk, mv := range cm {
		// Again, unwrap token value if line check is required.
		tk, mv = unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "type":
			cache, ok := mv.(string)
			if !ok {
				return nil, &configErr{tk, fmt.Sprintf("error parsing ocsp cache config, unknown field [%q]", mk)}
			}
			cacheType, exists := certidp.CacheTypeMap[strings.ToLower(cache)]
			if !exists {
				return nil, &configErr{tk, fmt.Sprintf("error parsing ocsp cache config, unknown cache type [%s]", cache)}
			}
			pcfg.Type = cacheType
		default:
			return nil, &configErr{tk, "error parsing ocsp cache config, unknown field"}
		}
	}

	return pcfg, nil
}
