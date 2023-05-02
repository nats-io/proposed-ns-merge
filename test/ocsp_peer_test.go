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

package test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/nats-io/nats.go"
)

func newOCSPResponderRootCA(t *testing.T) *http.Server {
	t.Helper()
	respCertPEM := "configs/certs/ocsp_peer/mini-ca/caocsp/caocsp_cert.pem"
	respKeyPEM := "configs/certs/ocsp_peer/mini-ca/caocsp/private/caocsp_keypair.pem"
	issuerCertPEM := "configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"
	return newOCSPResponderDesignated(t, issuerCertPEM, respCertPEM, respKeyPEM, true, "127.0.0.1:8888")
}

func newOCSPResponderIntermediateCA1(t *testing.T) *http.Server {
	t.Helper()
	respCertPEM := "configs/certs/ocsp_peer/mini-ca/ocsp1/ocsp1_bundle.pem"
	respKeyPEM := "configs/certs/ocsp_peer/mini-ca/ocsp1/private/ocsp1_keypair.pem"
	issuerCertPEM := "configs/certs/ocsp_peer/mini-ca/intermediate1/intermediate1_cert.pem"
	return newOCSPResponderDesignated(t, issuerCertPEM, respCertPEM, respKeyPEM, true, "127.0.0.1:18888")
}

func newOCSPResponderIntermediateCA2(t *testing.T) *http.Server {
	t.Helper()
	respCertPEM := "configs/certs/ocsp_peer/mini-ca/ocsp2/ocsp2_bundle.pem"
	respKeyPEM := "configs/certs/ocsp_peer/mini-ca/ocsp2/private/ocsp2_keypair.pem"
	issuerCertPEM := "configs/certs/ocsp_peer/mini-ca/intermediate2/intermediate2_cert.pem"
	return newOCSPResponderDesignated(t, issuerCertPEM, respCertPEM, respKeyPEM, true, "127.0.0.1:28888")
}

// TestOCSPPeerGoodClients is test of two NATS client (AIA enabled at leaf and cert) under good path (different intermediates)
func TestOCSPPeerGoodClients(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rootCAResponder := newOCSPResponderRootCA(t)
	rootCAResponderURL := fmt.Sprintf("http://%s", rootCAResponder.Addr)
	defer rootCAResponder.Shutdown(ctx)
	setOCSPStatus(t, rootCAResponderURL, "configs/certs/ocsp_peer/mini-ca/intermediate1/intermediate1_cert.pem", ocsp.Good)
	setOCSPStatus(t, rootCAResponderURL, "configs/certs/ocsp_peer/mini-ca/intermediate2/intermediate2_cert.pem", ocsp.Good)

	intermediateCA1Responder := newOCSPResponderIntermediateCA1(t)
	intermediateCA1ResponderURL := fmt.Sprintf("http://%s", intermediateCA1Responder.Addr)
	defer intermediateCA1Responder.Shutdown(ctx)
	setOCSPStatus(t, intermediateCA1ResponderURL, "configs/certs/ocsp_peer/mini-ca/client1/UserA1_cert.pem", ocsp.Good)

	intermediateCA2Responder := newOCSPResponderIntermediateCA2(t)
	intermediateCA2ResponderURL := fmt.Sprintf("http://%s", intermediateCA2Responder.Addr)
	defer intermediateCA2Responder.Shutdown(ctx)
	setOCSPStatus(t, intermediateCA2ResponderURL, "configs/certs/ocsp_peer/mini-ca/client2/UserB1_cert.pem", ocsp.Good)

	for _, test := range []struct {
		name      string
		config    string
		opts      []nats.Option
		err       error
		rerr      error
		configure func()
	}{
		{
			"mTLS OCSP peer check on inbound client connection, client of intermediate CA 1",
			`
				port: -1

				tls: {
					cert_file: "configs/certs/ocsp_peer/mini-ca/server1/TestServer1_bundle.pem"
					key_file: "configs/certs/ocsp_peer/mini-ca/server1/private/TestServer1_keypair.pem"
					ca_file: "configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"
					timeout: 5
					verify: true

					# Explicit enable and no cache
					ocsp_peer: {
						verify: true
						ca_timeout: 5
						allowed_clockskew: 30
					}
				}
			`,
			[]nats.Option{
				nats.ClientCert("./configs/certs/ocsp_peer/mini-ca/client1/UserA1_bundle.pem", "./configs/certs/ocsp_peer/mini-ca/client1/private/UserA1_keypair.pem"),
				nats.RootCAs("./configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"),
				nats.ErrorHandler(noOpErrHandler),
			},
			nil,
			nil,
			func() {},
		},
		{
			"mTLS OCSP peer check on inbound client connection, client of intermediate CA 2",
			`
				port: -1

				tls: {
					cert_file: "configs/certs/ocsp_peer/mini-ca/server1/TestServer1_bundle.pem"
					key_file: "configs/certs/ocsp_peer/mini-ca/server1/private/TestServer1_keypair.pem"
					ca_file: "configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"
					timeout: 5
					verify: true

					# Setting to true accepts all defaults and no cache
					ocsp_peer: true
				}
			`,
			[]nats.Option{
				nats.ClientCert("./configs/certs/ocsp_peer/mini-ca/client2/UserB1_bundle.pem", "./configs/certs/ocsp_peer/mini-ca/client2/private/UserB1_keypair.pem"),
				nats.RootCAs("./configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"),
				nats.ErrorHandler(noOpErrHandler),
			},
			nil,
			nil,
			func() {},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.configure()
			content := test.config
			conf := createConfFile(t, []byte(content))
			s, opts := RunServerWithConfig(conf)
			defer s.Shutdown()

			nc, err := nats.Connect(fmt.Sprintf("tls://localhost:%d", opts.Port), test.opts...)
			if test.err == nil && err != nil {
				t.Errorf("Expected to connect, got %v", err)
			} else if test.err != nil && err == nil {
				t.Errorf("Expected error on connect")
			} else if test.err != nil && err != nil {
				// Error on connect was expected
				if test.err.Error() != err.Error() {
					t.Errorf("Expected error %s, got: %s", test.err, err)
				}
				return
			}
			defer nc.Close()

			nc.Subscribe("ping", func(m *nats.Msg) {
				m.Respond([]byte("pong"))
			})
			nc.Flush()

			_, err = nc.Request("ping", []byte("ping"), 250*time.Millisecond)
			if test.rerr != nil && err == nil {
				t.Errorf("Expected error getting response")
			} else if test.rerr == nil && err != nil {
				t.Errorf("Expected response")
			}
		})
	}
}

// TestOCSPPeerUnknownClient is test of NATS client that is OCSP status Unknown from its OCSP Responder
func TestOCSPPeerUnknownClient(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rootCAResponder := newOCSPResponderRootCA(t)
	rootCAResponderURL := fmt.Sprintf("http://%s", rootCAResponder.Addr)
	defer rootCAResponder.Shutdown(ctx)
	setOCSPStatus(t, rootCAResponderURL, "configs/certs/ocsp_peer/mini-ca/intermediate1/intermediate1_cert.pem", ocsp.Good)

	intermediateCA1Responder := newOCSPResponderIntermediateCA1(t)
	defer intermediateCA1Responder.Shutdown(ctx)

	for _, test := range []struct {
		name      string
		config    string
		opts      []nats.Option
		err       error
		rerr      error
		configure func()
	}{
		{
			"mTLS OCSP peer check on inbound client connection, client unknown to intermediate CA 1",
			`
				port: -1

				tls: {
					cert_file: "configs/certs/ocsp_peer/mini-ca/server1/TestServer1_bundle.pem"
					key_file: "configs/certs/ocsp_peer/mini-ca/server1/private/TestServer1_keypair.pem"
					ca_file: "configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"
					timeout: 5
					verify: true

					ocsp_peer: true
				}
			`,
			[]nats.Option{
				nats.ClientCert("./configs/certs/ocsp_peer/mini-ca/client1/UserA1_bundle.pem", "./configs/certs/ocsp_peer/mini-ca/client1/private/UserA1_keypair.pem"),
				nats.RootCAs("./configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"),
				nats.ErrorHandler(noOpErrHandler),
			},
			errors.New("remote error: tls: bad certificate"),
			errors.New("expect error"),
			func() {},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.configure()
			content := test.config
			conf := createConfFile(t, []byte(content))
			s, opts := RunServerWithConfig(conf)
			defer s.Shutdown()

			nc, err := nats.Connect(fmt.Sprintf("tls://localhost:%d", opts.Port), test.opts...)
			if test.err == nil && err != nil {
				t.Errorf("Expected to connect, got %v", err)
			} else if test.err != nil && err == nil {
				t.Errorf("Expected error on connect")
			} else if test.err != nil && err != nil {
				// Error on connect was expected
				if test.err.Error() != err.Error() {
					t.Errorf("Expected error %s, got: %s", test.err, err)
				}
				return
			}
			defer nc.Close()

			t.Errorf("Expected connection error, fell through")
		})
	}
}

// TestOCSPPeerRevokedClient is test of NATS client that is OCSP status Revoked from its OCSP Responder
func TestOCSPPeerRevokedClient(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rootCAResponder := newOCSPResponderRootCA(t)
	rootCAResponderURL := fmt.Sprintf("http://%s", rootCAResponder.Addr)
	defer rootCAResponder.Shutdown(ctx)
	setOCSPStatus(t, rootCAResponderURL, "configs/certs/ocsp_peer/mini-ca/intermediate1/intermediate1_cert.pem", ocsp.Good)

	intermediateCA1Responder := newOCSPResponderIntermediateCA1(t)
	intermediateCA1ResponderURL := fmt.Sprintf("http://%s", intermediateCA1Responder.Addr)
	defer intermediateCA1Responder.Shutdown(ctx)
	setOCSPStatus(t, intermediateCA1ResponderURL, "configs/certs/ocsp_peer/mini-ca/client1/UserA1_cert.pem", ocsp.Revoked)

	for _, test := range []struct {
		name      string
		config    string
		opts      []nats.Option
		err       error
		rerr      error
		configure func()
	}{
		{
			"mTLS OCSP peer check on inbound client connection, client revoked by intermediate CA 1",
			`
				port: -1

				tls: {
					cert_file: "configs/certs/ocsp_peer/mini-ca/server1/TestServer1_bundle.pem"
					key_file: "configs/certs/ocsp_peer/mini-ca/server1/private/TestServer1_keypair.pem"
					ca_file: "configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"
					timeout: 5
					verify: true

					# Turn on CA OCSP check so this revoked client should NOT be able to connect
					ocsp_peer: true
				}
			`,
			[]nats.Option{
				nats.ClientCert("./configs/certs/ocsp_peer/mini-ca/client1/UserA1_bundle.pem", "./configs/certs/ocsp_peer/mini-ca/client1/private/UserA1_keypair.pem"),
				nats.RootCAs("./configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"),
				nats.ErrorHandler(noOpErrHandler),
			},
			errors.New("remote error: tls: bad certificate"),
			errors.New("expect error"),
			func() {},
		},
		{
			"mTLS OCSP peer check on inbound client connection, client revoked by intermediate CA 1 but no OCSP check",
			`
				port: -1

				tls: {
					cert_file: "configs/certs/ocsp_peer/mini-ca/server1/TestServer1_bundle.pem"
					key_file: "configs/certs/ocsp_peer/mini-ca/server1/private/TestServer1_keypair.pem"
					ca_file: "configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"
					timeout: 5
					verify: true

					# Explicit disable of OCSP peer check
					ocsp_peer: false
				}
			`,
			[]nats.Option{
				nats.ClientCert("./configs/certs/ocsp_peer/mini-ca/client1/UserA1_bundle.pem", "./configs/certs/ocsp_peer/mini-ca/client1/private/UserA1_keypair.pem"),
				nats.RootCAs("./configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"),
				nats.ErrorHandler(noOpErrHandler),
			},
			nil,
			nil,
			func() {},
		},
		{
			"mTLS OCSP peer check on inbound client connection, client revoked by intermediate CA 1 but no OCSP check",
			`
				port: -1

				tls: {
					cert_file: "configs/certs/ocsp_peer/mini-ca/server1/TestServer1_bundle.pem"
					key_file: "configs/certs/ocsp_peer/mini-ca/server1/private/TestServer1_keypair.pem"
					ca_file: "configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"
					timeout: 5
					verify: true

					# Implicit disable of OCSP peer check (i.e. not configured)
					# ocsp_peer: false
				}
			`,
			[]nats.Option{
				nats.ClientCert("./configs/certs/ocsp_peer/mini-ca/client1/UserA1_bundle.pem", "./configs/certs/ocsp_peer/mini-ca/client1/private/UserA1_keypair.pem"),
				nats.RootCAs("./configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"),
				nats.ErrorHandler(noOpErrHandler),
			},
			nil,
			nil,
			func() {},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.configure()
			content := test.config
			conf := createConfFile(t, []byte(content))
			s, opts := RunServerWithConfig(conf)
			defer s.Shutdown()

			nc, err := nats.Connect(fmt.Sprintf("tls://localhost:%d", opts.Port), test.opts...)
			if test.err == nil && err != nil {
				t.Errorf("Expected to connect, got %v", err)
			} else if test.err != nil && err == nil {
				t.Errorf("Expected error on connect")
			} else if test.err != nil && err != nil {
				// Error on connect was expected
				if test.err.Error() != err.Error() {
					t.Errorf("Expected error %s, got: %s", test.err, err)
				}
				return
			}
			defer nc.Close()
		})
	}
}

// TestOCSPPeerUnknownAndRevokedIntermediate test of NATS client that is OCSP good but either its intermediate is unknown or revoked
func TestOCSPPeerUnknownAndRevokedIntermediate(t *testing.T) {

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rootCAResponder := newOCSPResponderRootCA(t)
	rootCAResponderURL := fmt.Sprintf("http://%s", rootCAResponder.Addr)
	defer rootCAResponder.Shutdown(ctx)
	setOCSPStatus(t, rootCAResponderURL, "configs/certs/ocsp_peer/mini-ca/intermediate1/intermediate1_cert.pem", ocsp.Revoked)
	// No test OCSP status set on intermediate2, so unknown

	intermediateCA1Responder := newOCSPResponderIntermediateCA1(t)
	intermediateCA1ResponderURL := fmt.Sprintf("http://%s", intermediateCA1Responder.Addr)
	defer intermediateCA1Responder.Shutdown(ctx)
	setOCSPStatus(t, intermediateCA1ResponderURL, "configs/certs/ocsp_peer/mini-ca/client1/UserA1_cert.pem", ocsp.Good)

	intermediateCA2Responder := newOCSPResponderIntermediateCA2(t)
	intermediateCA2ResponderURL := fmt.Sprintf("http://%s", intermediateCA2Responder.Addr)
	defer intermediateCA2Responder.Shutdown(ctx)
	setOCSPStatus(t, intermediateCA2ResponderURL, "configs/certs/ocsp_peer/mini-ca/client2/UserB1_cert.pem", ocsp.Good)

	for _, test := range []struct {
		name      string
		config    string
		opts      []nats.Option
		err       error
		rerr      error
		configure func()
	}{
		{
			"mTLS OCSP peer check on inbound client connection, client's intermediate is revoked",
			`
				port: -1

				tls: {
					cert_file: "configs/certs/ocsp_peer/mini-ca/server1/TestServer1_bundle.pem"
					key_file: "configs/certs/ocsp_peer/mini-ca/server1/private/TestServer1_keypair.pem"
					ca_file: "configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"
					timeout: 5
					verify: true

					ocsp_peer: true
				}
			`,
			[]nats.Option{
				nats.ClientCert("./configs/certs/ocsp_peer/mini-ca/client1/UserA1_bundle.pem", "./configs/certs/ocsp_peer/mini-ca/client1/private/UserA1_keypair.pem"),
				nats.RootCAs("./configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"),
				nats.ErrorHandler(noOpErrHandler),
			},
			errors.New("remote error: tls: bad certificate"),
			errors.New("expect error"),
			func() {},
		},
		{
			"mTLS OCSP peer check on inbound client connection, client's intermediate is unknown'",
			`
				port: -1

				tls: {
					cert_file: "configs/certs/ocsp_peer/mini-ca/server1/TestServer1_bundle.pem"
					key_file: "configs/certs/ocsp_peer/mini-ca/server1/private/TestServer1_keypair.pem"
					ca_file: "configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"
					timeout: 5
					verify: true

					ocsp_peer: true
				}
			`,
			[]nats.Option{
				nats.ClientCert("./configs/certs/ocsp_peer/mini-ca/client2/UserB1_bundle.pem", "./configs/certs/ocsp_peer/mini-ca/client2/private/UserB1_keypair.pem"),
				nats.RootCAs("./configs/certs/ocsp_peer/mini-ca/root/root_cert.pem"),
				nats.ErrorHandler(noOpErrHandler),
			},
			errors.New("remote error: tls: bad certificate"),
			errors.New("expect error"),
			func() {},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.configure()
			content := test.config
			conf := createConfFile(t, []byte(content))
			s, opts := RunServerWithConfig(conf)
			defer s.Shutdown()

			nc, err := nats.Connect(fmt.Sprintf("tls://localhost:%d", opts.Port), test.opts...)
			if test.err == nil && err != nil {
				t.Errorf("Expected to connect, got %v", err)
			} else if test.err != nil && err == nil {
				t.Errorf("Expected error on connect")
			} else if test.err != nil && err != nil {
				// Error on connect was expected
				if test.err.Error() != err.Error() {
					t.Errorf("Expected error %s, got: %s", test.err, err)
				}
				return
			}
			defer nc.Close()

			t.Errorf("Expected connection error, fell through")
		})
	}
}
