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
