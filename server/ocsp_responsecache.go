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
	"fmt"
	"strings"

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
	Put(fingerprint string, resp ocsp.Response, log *certidp.Log)
	Get(fingerprint string, log *certidp.Log) *ocsp.Response
	Delete(fingerprint string, log *certidp.Log)
	Online() bool
	Config() *OCSPResponseCacheConfig
}

// NoOpCache is a no-op implementation of OCSPResponseCache for consistent runtime implementation of verification
type NoOpCache struct {
	config *OCSPResponseCacheConfig
	online bool
}

func (c *NoOpCache) Put(fingerprint string, _ ocsp.Response, log *certidp.Log) {
	if fingerprint == "" || log == nil {
		return
	}
	log.Debugf("OCSP response cache, Put() not implemented")
}

func (c *NoOpCache) Get(fingerprint string, log *certidp.Log) *ocsp.Response {
	if fingerprint == "" || log == nil {
		return nil
	}
	log.Debugf("OCSP response cache, Get() not implemented")
	return nil
}

func (c *NoOpCache) Delete(fingerprint string, log *certidp.Log) {
	if fingerprint == "" || log == nil {
		return
	}
	log.Debugf("OCSP response cache, Delete() not implemented")
}

func (c *NoOpCache) Online() bool {
	return c.online
}

func (c *NoOpCache) Config() *OCSPResponseCacheConfig {
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
	   type: <none, shared, local>
	   # JS-enabled account name for "shared" response cache
	   account: "MY_ACCOUNT"
	   # KV-bucket name for "shared" response cache
	   bucket: "MY_BUCKET"
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
	default:
		s.Fatalf("unimplemented OCSP response cache type: %v", cc.Type)
	}

	// TODO(tgb) configurable account options and checks
	//ocspAcct, _ := s.LookupOrRegisterAccount("$OCSPACCT")
	//if ocspAcct == nil {
	//	ocspResponseCache.Enabled = false
	//	s.Errorf("error enabling OCSP response cache account")
	//	return
	//}
	//if err := ocspAcct.EnableJetStream(nil); err != nil {
	//	s.Errorf("error enabling OCSP response cache account: %v", err)
	//	ocspResponseCache.Enabled = false
	//	return
	//}

	// validate setups

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
		case "account":
			pcfg.AccountStr = mv.(string)
		case "bucket":
			pcfg.BucketStr = mv.(string)
		default:
			return nil, &configErr{tk, "error parsing ocsp cache config, unknown field"}
		}
	}

	// TODO(tgb) - validate type against necessary related configurations by operator
	// TODO(tgb) - alter this override to no-op cache when other cache implementations available
	pcfg.Type = certidp.NONE

	return pcfg, nil
}
