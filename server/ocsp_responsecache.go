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

// TODO(tgb) - implicit account, JS enabled for the response cache and all routines

type ocspResponseCacheConfig struct {
	ocspAcct *Account
	enabled  bool
}

var ocspResponseCache *ocspResponseCacheConfig = &ocspResponseCacheConfig{
	ocspAcct: nil,
	enabled:  false,
}

func (s *Server) initOCSPResponseCache() {
	if !ocspPeerVerify || ocspResponseCache.ocspAcct != nil {
		return
	}

	// TODO(tgb) configurable account options and checks
	ocspAcct, _ := s.LookupOrRegisterAccount("$OCSPACCT")
	if ocspAcct == nil {
		ocspResponseCache.enabled = false
		s.Errorf("error enabling OCSP response cache account")
		return
	}
	if err := ocspAcct.EnableJetStream(nil); err != nil {
		s.Errorf("error enabling OCSP response cache account: %v", err)
		ocspResponseCache.enabled = false
		return
	}

	// validate setups

	ocspResponseCache.enabled = true
}
