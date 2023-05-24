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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/nats-io/nats-server/v2/server/certidp"
)

func parseOCSPPeer(v interface{}) (pcfg *certidp.OCSPPeerConfig, retError error) {
	var lt token
	defer convertPanicToError(&lt, &retError)

	tk, v := unwrapValue(v, &lt)
	cm, ok := v.(map[string]interface{})
	if !ok {
		return nil, &configErr{tk, fmt.Sprintf("expected map to define OCSP peer opts, got [%T]", v)}
	}

	pcfg = &certidp.OCSPPeerConfig{}
	retError = nil

	for mk, mv := range cm {
		// Again, unwrap token value if line check is required.
		tk, mv = unwrapValue(mv, &lt)
		switch strings.ToLower(mk) {
		case "verify":
			verify, ok := mv.(bool)
			if !ok {
				return nil, &configErr{tk, fmt.Sprintf("error parsing tls peer config, unknown field [%q]", mk)}
			}
			pcfg.Verify = verify
		case "allowed_clockskew":
			at := float64(0)
			switch mv := mv.(type) {
			case int64:
				at = float64(mv)
			case float64:
				at = mv
			case string:
				d, err := time.ParseDuration(mv)
				if err != nil {
					return nil, &configErr{tk, fmt.Sprintf("error parsing tls peer config, 'allowed_clockskew' %s", err)}
				}
				at = d.Seconds()
			default:
				return nil, &configErr{tk, "error parsing tls peer config, 'allowed_clockskew' wrong type"}
			}
			pcfg.ClockSkew = at
		case "ca_timeout":
			at := float64(0)
			switch mv := mv.(type) {
			case int64:
				at = float64(mv)
			case float64:
				at = mv
			case string:
				d, err := time.ParseDuration(mv)
				if err != nil {
					return nil, &configErr{tk, fmt.Sprintf("error parsing tls peer config, 'ca_timeout' %s", err)}
				}
				at = d.Seconds()
			default:
				return nil, &configErr{tk, "error parsing tls peer config, 'ca_timeout' wrong type"}
			}
			pcfg.Timeout = at
		default:
			return nil, &configErr{tk, "error parsing tls peer config, unknown field"}
		}
	}
	return pcfg, nil
}

// mTLS OCSP and Leaf OCSP
func (s *Server) plugTLSOCSPPeer(config *tlsConfigKind) (*tls.Config, bool, error) {
	if config == nil || config.tlsConfig == nil {
		return nil, false, errors.New("unable to plug TLS verify connection, config is nil")
	}
	s.Debugf("Plugging TLS OCSP peer for [%s]", config.kind)

	kind := config.kind
	isSpoke := config.isLeafSpoke
	tcOpts := config.tlsOpts

	if tcOpts == nil || tcOpts.OCSPPeerConfig == nil || !tcOpts.OCSPPeerConfig.Verify {
		return nil, false, nil
	}

	// peer is a tls client
	if kind == kindStringMap[CLIENT] || (kind == kindStringMap[LEAF] && !isSpoke) {
		if !tcOpts.Verify {
			return nil, false, errors.New("OCSP peer verification for client connections requires TLS verify (mTLS) to be enabled")
		}
		return s.plugClientTLSOCSPPeer(config)
	}

	// peer is a tls server
	if kind == kindStringMap[LEAF] && isSpoke {
		return s.plugServerTLSOCSPPeer(config)
	}

	return nil, false, nil
}

func (s *Server) plugClientTLSOCSPPeer(config *tlsConfigKind) (*tls.Config, bool, error) {
	if config == nil || config.tlsConfig == nil || config.tlsOpts == nil {
		return nil, false, errors.New("unable to register client OCSP verification")
	}

	tc := config.tlsConfig
	tcOpts := config.tlsOpts

	if tcOpts.OCSPPeerConfig == nil || !tcOpts.OCSPPeerConfig.Verify {
		return tc, false, nil
	}

	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		if !s.tlsClientOCSPValid(cs.VerifiedChains, tcOpts.OCSPPeerConfig) {
			return errors.New("client not OCSP valid")
		}
		return nil
	}

	return tc, true, nil
}

func (s *Server) plugServerTLSOCSPPeer(config *tlsConfigKind) (*tls.Config, bool, error) {
	if config == nil || config.tlsConfig == nil || config.tlsOpts == nil {
		return nil, false, errors.New("unable to register server OCSP verification")
	}

	tc := config.tlsConfig
	tcOpts := config.tlsOpts

	if tcOpts.OCSPPeerConfig == nil || !tcOpts.OCSPPeerConfig.Verify {
		return tc, false, nil
	}

	tc.VerifyConnection = func(cs tls.ConnectionState) error {
		if !s.tlsServerOCSPValid(cs.VerifiedChains, tcOpts.OCSPPeerConfig) {
			return errors.New("server not OCSP valid")
		}
		return nil
	}
	return tc, true, nil
}

// tlsServerOCSPValid evaluates verified chains (post successful TLS handshake) against OCSP
// eligibility. A verified chain is considered OCSP Valid if either none of the links are
// OCSP eligible, or current "good" responses from the CA can be obtained for each eligible link.
// Upon first OCSP Valid chain found, the Server is deemed OCSP Valid. If none of the chains are
// OCSP Valid, the Server is deemed OCSP Invalid. A verified self-signed certificate (chain length 1)
// is also considered OCSP Valid.
func (s *Server) tlsServerOCSPValid(chains [][]*x509.Certificate, opts *certidp.OCSPPeerConfig) bool {
	s.Debugf("Peer OCSP enabled: [%d] TLS server chain(s) will be evaluated", len(chains))
	return s.peerOCSPValid(chains, opts)
}

// tlsClientOCSPValid evaluates verified chains (post successful TLS handshake) against OCSP
// eligibility. A verified chain is considered OCSP Valid if either none of the links are
// OCSP eligible, or current "good" responses from the CA can be obtained for each eligible link.
// Upon first OCSP Valid chain found, the Client is deemed OCSP Valid. If none of the chains are
// OCSP Valid, the Client is deemed OCSP Invalid. A verified self-signed certificate (chain length 1)
// is also considered OCSP Valid.
func (s *Server) tlsClientOCSPValid(chains [][]*x509.Certificate, opts *certidp.OCSPPeerConfig) bool {
	s.Debugf("Peer OCSP enabled: %d TLS client chain(s) will be evaluated", len(chains))
	return s.peerOCSPValid(chains, opts)
}

func (s *Server) peerOCSPValid(chains [][]*x509.Certificate, opts *certidp.OCSPPeerConfig) bool {
	for ci, chain := range chains {
		s.Debugf("Chain [%d]: %d total link(s)", ci, len(chain))
		// verified self-signed certificate is Client OCSP Valid

		if len(chain) == 1 {
			s.Debugf("Chain [%d] is self-signed, thus peer is valid", ci)
			return true
		}

		// check if any of the links in the chain are OCSP eligible
		chainEligible := false
		var eligibleLinks []*certidp.ChainLink

		// iterate over links skipping the root cert which is not OCSP eligible (self == issuer)
		for linkPos := 0; linkPos < len(chain)-1; linkPos++ {
			cert := chain[linkPos]
			link := &certidp.ChainLink{
				Leaf: cert,
			}
			if certidp.CertOCSPEligible(link) {
				chainEligible = true
				issuerCert := certidp.GetLeafIssuerCert(&chain, linkPos)
				if issuerCert == nil {
					// unexpected chain condition, reject Client as OCSP Invalid
					return false
				}
				link.Issuer = issuerCert
				eligibleLinks = append(eligibleLinks, link)
			}
		}

		// A verified chain (i.e. against our trust store) that is not OCSP eligible is always OCSP Valid
		if !chainEligible {
			s.Debugf("Chain [%d] has no OCSP eligible links, thus peer is valid", ci)
			// no links in the chain are OCSP eligible so verified chain is Client OSCP Valid
			return true
		}

		s.Debugf("Chain [%d] has %d OCSP eligible link(s)", ci, len(eligibleLinks))
		// verified chain has at least one OCSP eligible link, so check each eligible link
		// any link with a !good OCSP response makes the whole chain OCSP Invalid
		chainValid := true
		for _, link := range eligibleLinks {
			if good := s.certOCSPGood(link, opts); !good {
				chainValid = false
				break
			}
		}

		if chainValid {
			s.Debugf("Chain [%d] is OCSP valid for all eligible links, thus peer is valid", ci)
			return true
		}
	}

	// if we are here, all chains had OCSP eligible links, but none of the chains achived OCSP valid
	s.Debugf("No OCSP valid chains, thus peer is invalid")
	return false
}

func (s *Server) certOCSPGood(link *certidp.ChainLink, opts *certidp.OCSPPeerConfig) bool {
	if link == nil || link.Leaf == nil || link.Issuer == nil || link.OCSPWebEndpoints == nil || len(*link.OCSPWebEndpoints) < 1 {
		return false
	}

	var err error

	sLogs := &certidp.Log{
		Debugf:  s.Debugf,
		Noticef: s.Noticef,
		Warnf:   s.Warnf,
		Errorf:  s.Errorf,
		Tracef:  s.Tracef,
	}

	// cache check here, keyed by fingerprint (hash) of the link's cert
	// if the peer's cert (or peer's intermediate certs) change in any way, will be rc cache miss
	fingerprint := certidp.GenerateFingerprint(link.Leaf)

	// debug/informative only
	subj := strings.TrimSuffix(fmt.Sprintf("%s+", link.Leaf.Subject.ToRDNSequence()), "+")

	// TODO(tgb) - should we add a no_cache bool option for each TLS ocsp_peer block?
	// TODO(tgb) - check and implement option to allow failed CA fetch and use cached Revoked responses only...
	// TODO(tgb) - introduce option to allow responder Unknown as "good"?

	var rawResp []byte
	var ocspr *ocsp.Response
	var useCachedResp bool
	var rc = s.ocsprc

	// Check our cache before calling out to the CA OCSP responder
	s.Debugf("Checking OCSP response cache for [%s], key [%s]", subj, fingerprint)
	if rawResp = rc.Get(fingerprint, sLogs); rawResp != nil && len(rawResp) > 0 {
		ocspr, err = ocsp.ParseResponse(rawResp, link.Issuer)
		if err == nil && ocspr != nil {
			if certidp.OCSPResponseCurrent(ocspr, opts, sLogs) {
				useCachedResp = true
			} else {
				// cached response is not current, delete it
				rc.Delete(fingerprint, sLogs)
			}
		}
	}

	if !useCachedResp {
		// CA OCSP responder callout
		rawResp, err = certidp.FetchOCSPResponse(link, opts, sLogs)
		if err != nil || rawResp == nil || len(rawResp) == 0 {
			s.Debugf("OCSP response fetch error: %s", err)
			return false
		}

		ocspr, err = ocsp.ParseResponse(rawResp, link.Issuer)
		if err == nil && ocspr != nil {
			if !certidp.OCSPResponseCurrent(ocspr, opts, sLogs) {
				return false
			}
		} else {
			s.Debugf("OCSP response parse error: %s", err)
			return false
		}

		// cache the valid CA OCSP Response
		// fingerprint is cache key, subject is informational/debug since not unique for this purpose
		rc.Put(fingerprint, ocspr, subj, sLogs)
	}

	if ocspr.Status != ocsp.Good {
		s.Debugf("OCSP fail for [%s]", subj)
		return false
	}
	s.Debugf("OCSP pass for [%s]", subj)
	return true
}
