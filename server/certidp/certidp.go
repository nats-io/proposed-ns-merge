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
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	DefaultAllowedClockSkew     = 30 * time.Second
	DefaultOCSPResponderTimeout = 2 * time.Second
)

type StatusAssertion int

var (
	StatusAssertionStrToVal = map[string]StatusAssertion{
		"good":    ocsp.Good,
		"revoked": ocsp.Revoked,
		"unknown": ocsp.Unknown,
	}
	StatusAssertionValToStr = map[StatusAssertion]string{
		ocsp.Good:    "good",
		ocsp.Revoked: "revoked",
		ocsp.Unknown: "unknown",
	}
	StatusAssertionIntToVal = map[int]StatusAssertion{
		0: ocsp.Good,
		1: ocsp.Revoked,
		2: ocsp.Unknown,
	}
)

func (sa StatusAssertion) MarshalJSON() ([]byte, error) {
	var str string
	str, ok := StatusAssertionValToStr[sa]
	if !ok {
		// set unknown as fallback
		str = StatusAssertionValToStr[ocsp.Unknown]
	}
	return json.Marshal(str)
}

func (sa *StatusAssertion) UnmarshalJSON(in []byte) error {
	var v StatusAssertion
	v, ok := StatusAssertionStrToVal[strings.ReplaceAll(string(in), "\"", "")]
	if !ok {
		// set unknown as fallback
		v = StatusAssertionStrToVal["unknown"]
	}
	*sa = v
	return nil
}

type ChainLink struct {
	Leaf             *x509.Certificate
	Issuer           *x509.Certificate
	OCSPWebEndpoints *[]*url.URL
}

// OCSPPeerConfig holds the parsed OCSP peer configuration section of TLS configuration
type OCSPPeerConfig struct {
	Verify                 bool
	Timeout                float64
	ClockSkew              float64
	WarnOnly               bool
	UnknownIsGood          bool
	AllowWhenCAUnreachable bool
}

// Log is a neutral method of passign server loggers to plugins
type Log struct {
	Debugf  func(format string, v ...interface{})
	Noticef func(format string, v ...interface{})
	Warnf   func(format string, v ...interface{})
	Errorf  func(format string, v ...interface{})
	Tracef  func(format string, v ...interface{})
}

var OCSPPeerUsage = `
For client, leaf spoke (remotes), and leaf hub connections, you may enable OCSP peer validation:

    tls {
        ...
        # mTLS must be enabled (with exception of Leaf remotes)
        verify: true
        ...
        # short form enables with defaults
        ocsp_peer: true
        
        # long form includes settable options
        ocsp_peer {
           verify: true
           # OCSP responder timeout in seconds (may be fractional, default 2 seconds)
           ca_timeout: 2
           # Allowed skew between server and OCSP responder time in seconds (may be fractional, default 30 seconds)
           allowed_clockskew: 30
           # Warn-only and never reject connections (default false)
           warn_only: false
           # Treat response Unknown status as valid certificate (default false)
           unknown_is_good: false
           # Warn-only if no effective CA response can be obtained and no cached revocation exists (default false)
           allow_when_ca_unreachable: false
        }
        ...
    }

Note: OCSP validation for route and gateway connections is enabled using the 'ocsp' configuration option.
`

// GenerateFingerprint returns a base64-encoded SHA256 hash of the raw certificate
func GenerateFingerprint(cert *x509.Certificate) string {
	data := sha256.Sum256(cert.Raw)
	return base64.StdEncoding.EncodeToString(data[:])
}

func getWebEndpoints(uris *[]string) []*url.URL {
	var urls []*url.URL
	for _, uri := range *uris {
		endpoint, err := url.ParseRequestURI(uri)
		if err != nil {
			// skip invalid URLs
			continue
		}
		if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
			// skip non-web URLs
			continue
		}
		urls = append(urls, endpoint)
	}
	return urls
}

// CertOCSPEligible checks if the certificate's issuer has populated AIA with OCSP responder endpoint(s)
// and is thus eligible for OCSP validation
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

// GetLeafIssuerCert returns the issuer certificate of the leaf (positional) certificate in the chain
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

// OCSPResponseCurrent checks if the OCSP response is current (i.e. not expired and not future effective)
func OCSPResponseCurrent(ocspr *ocsp.Response, opts *OCSPPeerConfig, log *Log) bool {
	skew := time.Duration(opts.ClockSkew * float64(time.Second))
	if skew <= 0*time.Second {
		skew = DefaultAllowedClockSkew
	}
	// Time validation not handled by ParseResponse.
	// https://tools.ietf.org/html/rfc6960#section-4.2.2.1
	now := time.Now().UTC()
	if !ocspr.NextUpdate.IsZero() && ocspr.NextUpdate.Before(now.Add(-1*skew)) {
		t := ocspr.NextUpdate.Format(time.RFC3339Nano)
		nt := now.Format(time.RFC3339Nano)
		log.Debugf(DbgResponseExpired, t, nt, skew)
		return false
	}
	if ocspr.ThisUpdate.After(now.Add(skew)) {
		t := ocspr.ThisUpdate.Format(time.RFC3339Nano)
		nt := now.Format(time.RFC3339Nano)
		log.Debugf(DbgResponseFutureDated, t, nt, skew)
		return false
	}
	return true
}
