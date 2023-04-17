package certidp

import (
	"crypto/sha256"
	"crypto/x509"
	"net/url"
	"time"
)

// VerifyPeerConnOpts is a neutral passing struct for plugins ClientTLSVerifyConn and ServerTLSVerifyConn
type VerifyPeerConnOpts struct {
	VerifyPeerConn          bool
	VerifyPeerConnTimeout   float64
	VerifyPeerConnClockSkew float64
}

// Log is a neutral method of passign server loggers to plugins
type Log struct {
	Debugf  func(format string, v ...interface{})
	Noticef func(format string, v ...interface{})
	Warnf   func(format string, v ...interface{})
	Errorf  func(format string, v ...interface{})
	Tracef  func(format string, v ...interface{})
}

const AllowedClockSkew = 30 * time.Second

type ChainLink struct {
	Leaf             *x509.Certificate
	Issuer           *x509.Certificate
	OCSPWebEndpoints *[]*url.URL
}

var ResponseCache OCSPResponseCache = &NoOpCache{}

var _ = `
For clients, leaf spokes (remotes), and leaf hubs, you may enable post-handshake OCSP peer validation:

    tls {
        ...
        verify_peer_con: true
        # responder timeout in seconds (may be fractional)
        verify_peer_con_timeout:    2
        ...
    }

Note: OCSP validation is enabled for routes and gateways via the global 'ocsp' staple option.
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
