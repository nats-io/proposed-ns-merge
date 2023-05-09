// Copyright 2012-2018 The NATS Authors
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

//go:build windows
// +build windows

package server

import (
	"testing"

	"golang.org/x/sys/windows/svc"
)

func TestWindowsService(t *testing.T) {
	var (
		s       = New(DefaultOptions())
		changes = make(chan svc.ChangeRequest, 1)
		status  = make(chan svc.Status, 1)
	)

	wrapper := &winServiceWrapper{
		server: s,
	}
	go wrapper.Execute(nil, changes, status)

	if s := <-status; s.State != svc.StartPending {
		t.Fatalf("expected StartPending state")
	}
	if s := <-status; s.State != svc.Running {
		t.Fatalf("expected Running state")
	}
	changes <- svc.ChangeRequest{
		Cmd: svc.Shutdown,
	}
	if s := <-status; s.State != svc.StopPending {
		t.Fatalf("expected StopPending state")
	}
}
