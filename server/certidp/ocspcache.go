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
