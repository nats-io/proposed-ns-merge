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
	"golang.org/x/crypto/ocsp"
)

type OCSPResponseCache interface {
	Put(fingerprint string, resp ocsp.Response, log *Log)
	Get(fingerprint string, log *Log) *ocsp.Response
	Delete(fingerprint string, log *Log)
}

type NoOpCache struct{}

func (c *NoOpCache) Put(fingerprint string, _ ocsp.Response, log *Log) {
	if fingerprint == "" || log == nil {
		return
	}
	log.Debugf("OCSP response cache, Put() not implemented")
}

func (c *NoOpCache) Get(fingerprint string, log *Log) *ocsp.Response {
	if fingerprint == "" || log == nil {
		return nil
	}
	log.Debugf("OCSP response cache, Get() not implemented")
	return nil
}

func (c *NoOpCache) Delete(fingerprint string, log *Log) {
	if fingerprint == "" || log == nil {
		return
	}
	log.Debugf("OCSP response cache, Delete() not implemented")
}
