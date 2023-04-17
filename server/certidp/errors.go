package certidp

import (
	"errors"
	"fmt"
)

var (
	// ErrBadOCSPResponder represents lack of signature trust of the OCSP Responder
	ErrBadOCSPResponder = errors.New("OCSP responder not trusted")

	// ErrOCSPResponseExpired represents an expired OCSP response
	ErrOCSPResponseExpired = errors.New("OCSP response expired")

	// ErrOCSPResponseNotYetValid represents an OCSP response that is not yet valid
	ErrOCSPResponseNotYetValid = errors.New("OCSP response not yet valid")

	// ErrOCSPCheckPeerOptParseFail represents an error parsing the tls config
	ErrOCSPCheckPeerOptParseFail = errors.New("error parsing tls config, 'ocsp_check_peer' wrong type")

	// ErrOCSPTimeoutOptParseFail represents an error parsing the tls config
	ErrOCSPTimeoutOptParseFail = errors.New("error parsing tls config, 'ocsp_timeout' wrong type")

	ErrOCSPClientCheckWithoutMutualTLS = errors.New("OCSP client validation requires mTLS to be configured")

	ErrOCSPClientCheckFailed = fmt.Errorf("OCSP check rejected TLS client")

	ErrOCSPServerCheckFailed = fmt.Errorf("OCSP check rejected TLS server")

	ErrOCSPUnableToHookUnknown = errors.New("unknown error evaluating OCSP validation hooks")
)
