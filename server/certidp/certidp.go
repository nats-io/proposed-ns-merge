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

package certidp

import (
	"crypto/sha256"
	"crypto/x509"
	"net/url"
	"time"
)

const (
	AllowedClockSkew            = 30 * time.Second
	DefaultOCSPResponderTimeout = 2 * time.Second
)

type CacheType int

const (
	NONE CacheType = iota + 1
	SHARED
	LOCAL
)

var CacheTypeMap = map[string]CacheType{
	"none":   NONE,
	"shared": SHARED,
	"local":  LOCAL,
}

type ChainLink struct {
	Leaf             *x509.Certificate
	Issuer           *x509.Certificate
	OCSPWebEndpoints *[]*url.URL
}

// OCSPPeerConfig holds the parsed OCSP peer configuration section of TLS configuration
type OCSPPeerConfig struct {
	Verify    bool
	Timeout   float64
	ClockSkew float64
}

// Log is a neutral method of passign server loggers to plugins
type Log struct {
	Debugf  func(format string, v ...interface{})
	Noticef func(format string, v ...interface{})
	Warnf   func(format string, v ...interface{})
	Errorf  func(format string, v ...interface{})
	Tracef  func(format string, v ...interface{})
}

var _ = `
For client, leaf spoke (remotes), and leaf hub connections, you may enable OCSP peer validation:

    tls {
        ...
        ocsp_peer {
           verify: true
           # OCSP responder timeout in seconds (may be fractional)
           ca_timeout: 2
           # Allowed skew between server and OCSP responder time in seconds (may be fractional)
           allowed_clockskew: 30
           # Cache OCSP responses for the duration of the CA response validity period
           cache: <none, shared, local>
           # JS-enabled account name for "shared" response cache
           account: "MY_ACCOUNT"
           # KV-bucket name for "shared" response cache
           bucket: "MY_BUCKET"
        }
        ...
    }

Note: OCSP validation is enabled for routes and gateways via the server 'ocsp' staple option.
`

func GenerateFingerprint(cert *x509.Certificate) string {
	data := sha256.Sum256(cert.Raw)
	return string(data[:])
}

func getWebEndpoints(uris *[]string) []*url.URL {
	var urls []*url.URL
	for _, uri := range *uris {
		endpoint, err := url.ParseRequestURI(uri)
		if err != nil {
			// skip invalid URLs
			continue
		}

		// TODO(tgb): possibly skip https
		if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
			// skip non-web URLs
			continue
		}
		urls = append(urls, endpoint)
	}
	return urls
}

func CertOCSPEligible(link *ChainLink) bool {
	if link == nil || link.Leaf.Raw == nil || len(link.Leaf.Raw) == 0 {
		return false
	}
	if link.Leaf.OCSPServer == nil || len(link.Leaf.OCSPServer) == 0 {
		return false
	}
	urls := getWebEndpoints(&link.Leaf.OCSPServer)
	if len(urls) == 0 {
		return false
	}
	link.OCSPWebEndpoints = &urls
	return true
}

func GetLeafIssuerCert(chain *[]*x509.Certificate, leafPos int) *x509.Certificate {
	if chain == nil || len(*chain) == 0 || leafPos < 0 {
		return nil
	}
	// self-signed certificate or too-big leafPos
	if leafPos >= len(*chain)-1 {
		return nil
	}
	// returns pointer to issuer cert or nil
	return (*chain)[leafPos+1]
}
