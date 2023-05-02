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
