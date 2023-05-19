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
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/nats-io/nats-server/v2/server/certidp"
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
	Fingerprint string
	CachedAt    time.Time
	RespStatus  int
	RespExpires time.Time
	Resp        []byte
}

type OCSPResponseCache interface {
	Put(fingerprint string, resp *ocsp.Response, log *certidp.Log)
	Get(fingerprint string, log *certidp.Log) []byte
	Delete(fingerprint string, log *certidp.Log)
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

func (c *LocalCache) Put(fingerprint string, caResp *ocsp.Response, log *certidp.Log) {
	if !c.online || caResp == nil || fingerprint == "" {
		return
	}
	log.Debugf("Caching OCSP response for fingerprint %s", base64.StdEncoding.EncodeToString([]byte(fingerprint)))
	c.mux.Lock()
	defer c.mux.Unlock()
	item := OCSPResponseCacheItem{
		Fingerprint: fingerprint,
		RespStatus:  caResp.Status,
		Resp:        caResp.Raw,
	}
	c.cache[fingerprint] = item
	c.stats.Items = int64(len(c.cache))
}

func (c *LocalCache) Get(fingerprint string, log *certidp.Log) []byte {
	if !c.online || fingerprint == "" {
		return nil
	}
	c.mux.RLock()
	defer c.mux.RUnlock()
	val, ok := c.cache[fingerprint]
	if ok {
		atomic.AddInt64(&c.stats.Hits, 1)
		log.Debugf("OCSP response cache hit for fingerprint %s", base64.StdEncoding.EncodeToString([]byte(fingerprint)))
	} else {
		atomic.AddInt64(&c.stats.Misses, 1)
		log.Debugf("OCSP response cache miss for fingerprint %s", base64.StdEncoding.EncodeToString([]byte(fingerprint)))
		return nil
	}
	return val.Resp
}

func (c *LocalCache) Delete(fingerprint string, log *certidp.Log) {
	if !c.online || fingerprint == "" {
		return
	}
	log.Debugf("Deleting OCSP response for fingerprint %s", base64.StdEncoding.EncodeToString([]byte(fingerprint)))
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.cache, fingerprint)
	c.stats.Items = int64(len(c.cache))
}

func (c *LocalCache) Start(s *Server) {
	s.Debugf("Starting OCSP Response Cache...")
	// TODO(tgb) -- hydrate cache from disk here
	c.stats = &OCSPResponseCacheStats{}
	c.stats.Hits = 0
	c.stats.Misses = 0
	c.stats.Items = int64(len(c.cache))
	c.online = true
	return
}

func (c *LocalCache) Stop(s *Server) {
	s.Debugf("Stopping OCSP Response Cache...")
	c.online = false
	// TODO(tgb) -- dehydrate cache to disk here
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
