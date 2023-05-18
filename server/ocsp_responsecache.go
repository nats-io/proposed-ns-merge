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

	"golang.org/x/crypto/ocsp"

	"github.com/nats-io/nats-server/v2/server/certidp"
)

// TODO(tgb) - implicit account, JS enabled for the response cache and all routines

type OCSPResponseCacheConfig struct {
	Type       certidp.CacheType
	AccountStr string
	BucketStr  string
}

// ocspResponseCache is the current node-host scoped OCSP response cache; default noop impl and config struct
var ocspResponseCache OCSPResponseCache = &NoOpCache{
	config: &OCSPResponseCacheConfig{
		Type: certidp.NONE,
	},
	online: true,
}

type OCSPResponseCache interface {
	Put(fingerprint string, resp *ocsp.Response, log *certidp.Log)
	Get(fingerprint string, log *certidp.Log) *ocsp.Response
	Delete(fingerprint string, log *certidp.Log)
	Type() string
	Start(s *Server)
	Stop(s *Server)
	Online() bool
	Config() *OCSPResponseCacheConfig
}

// NoOpCache is a no-op implementation of OCSPResponseCache for consistent runtime implementation of verification
type NoOpCache struct {
	config *OCSPResponseCacheConfig
	online bool
}

func (c *NoOpCache) Put(_ string, _ *ocsp.Response, _ *certidp.Log) {
	return
}

func (c *NoOpCache) Get(_ string, _ *certidp.Log) *ocsp.Response {
	return nil
}

func (c *NoOpCache) Delete(_ string, _ *certidp.Log) {
	return
}

func (c *NoOpCache) Start(_ *Server) {
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
	return "none (no-op)"
}

func (c *NoOpCache) Config() *OCSPResponseCacheConfig {
	return c.config
}

// LocalCache is a local persistent implementation of OCSPResponseCache
type LocalCache struct {
	config *OCSPResponseCacheConfig
	online bool
	cache  map[string]*ocsp.Response
	mux    *sync.RWMutex
}

func (c *LocalCache) Put(fingerprint string, caResp *ocsp.Response, log *certidp.Log) {
	if !c.online || caResp == nil || fingerprint == "" {
		return
	}
	log.Debugf("Caching OCSP response for fingerprint %s", base64.StdEncoding.EncodeToString([]byte(fingerprint)))
	c.mux.Lock()
	defer c.mux.Unlock()
	c.cache[fingerprint] = caResp
}

func (c *LocalCache) Get(fingerprint string, log *certidp.Log) *ocsp.Response {
	if !c.online || fingerprint == "" {
		return nil
	}
	c.mux.RLock()
	defer c.mux.RUnlock()
	val := c.cache[fingerprint]
	if val != nil {
		log.Debugf("OCSP response cache hit for fingerprint %s", base64.StdEncoding.EncodeToString([]byte(fingerprint)))
	} else {
		log.Debugf("OCSP response cache miss for fingerprint %s", base64.StdEncoding.EncodeToString([]byte(fingerprint)))
	}
	return val
}

func (c *LocalCache) Delete(fingerprint string, log *certidp.Log) {
	if !c.online || fingerprint == "" {
		return
	}
	log.Debugf("Deleting OCSP response for fingerprint %s", base64.StdEncoding.EncodeToString([]byte(fingerprint)))
	c.mux.Lock()
	defer c.mux.Unlock()
	delete(c.cache, fingerprint)
}

func (c *LocalCache) Start(_ *Server) {
	c.online = true
	return
}

func (c *LocalCache) Stop(_ *Server) {
	c.online = false
	return
}

func (c *LocalCache) Online() bool {
	return c.online
}

func (c *LocalCache) Type() string {
	return "local (node persistence)"
}

func (c *LocalCache) Config() *OCSPResponseCacheConfig {
	return c.config
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
	if !ocspPeerVerify {
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
		ocspResponseCache = &NoOpCache{config: cc, online: true}
	case certidp.LOCAL:
		ocspResponseCache = &LocalCache{
			config: cc,
			online: false,
			cache:  make(map[string]*ocsp.Response),
			mux:    &sync.RWMutex{},
		}
	default:
		s.Fatalf("Unimplemented OCSP response cache type: %v", cc.Type)
	}
}

func (s *Server) startOCSPResponseCache() {
	// No mTLS OCSP or Leaf OCSP enablements, so no need to start cache
	if !ocspPeerVerify {
		return
	}

	// Starting the cache means different things depending on the selected implementation
	// from no-op to setting up NATS KV Client, and potentially creation of a Bucket
	ocspResponseCache.Start(s)

	if ocspResponseCache.Online() {
		s.Noticef("OCSP response cache online, type: %s", ocspResponseCache.Type())
	} else {
		s.Noticef("OCSP response cache offline, type: %s", ocspResponseCache.Type())
	}
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

	// TODO(tgb) - validate type against necessary related configurations by operator

	return pcfg, nil
}
