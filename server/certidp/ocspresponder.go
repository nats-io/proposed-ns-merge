package certidp

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

const defaultOCSPResponderTimeout = 2 * time.Second

func FetchOCSPResponse(link *ChainLink, opts *VerifyPeerConnOpts, log *Log) ([]byte, *ocsp.Response, error) {
	if link == nil || link.Leaf == nil || link.Issuer == nil || opts == nil || log == nil {
		return nil, nil, fmt.Errorf("invalid chain link")
	}

	timeout := time.Duration(opts.VerifyPeerConnTimeout * float64(time.Second))
	if timeout <= 0*time.Second {
		timeout = defaultOCSPResponderTimeout
	}

	getRequestBytes := func(u string, hc *http.Client) ([]byte, error) {
		resp, err := hc.Get(u)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("bad OCSP responder http status: %d", resp.StatusCode)
		}

		return io.ReadAll(resp.Body)
	}

	// Request documentation:
	// https://tools.ietf.org/html/rfc6960#appendix-A.1

	reqDER, err := ocsp.CreateRequest(link.Leaf, link.Issuer, nil)
	if err != nil {
		return nil, nil, err
	}

	reqEnc := base64.StdEncoding.EncodeToString(reqDER)

	responders := *link.OCSPWebEndpoints

	if len(responders) == 0 {
		return nil, nil, fmt.Errorf("no available ocsp servers")
	}

	var raw []byte

	hc := &http.Client{
		Timeout: timeout,
	}
	for _, u := range responders {
		url := u.String()
		log.Debugf("Trying OCSP responder url: %s", url)
		url = strings.TrimSuffix(url, "/")
		raw, err = getRequestBytes(fmt.Sprintf("%s/%s", url, reqEnc), hc)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("exhausted OCSP responders: %w", err)
	}

	resp, err := ocsp.ParseResponse(raw, link.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Get remote status: %w", err)
	}

	return raw, resp, nil
}
