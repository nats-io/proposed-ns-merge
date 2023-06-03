//go:build !windows

package test

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func createScriptFile(t testing.TB, content []byte) string {
	t.Helper()
	script, err := os.CreateTemp(t.TempDir(), "script-*.sh")
	if err != nil {
		t.Fatal(err)
	}
	fName := script.Name()
	script.Close()
	if err := os.WriteFile(fName, content, 0666); err != nil {
		t.Fatalf("Error writing conf file: %v", err)
	}
	return fName
}

// Note: script running policy must be enabled on your PC
// (As admin) Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

func runBashScript(scriptFile string, args []string, noWait bool) error {
	_ = args
	psExec, _ := exec.LookPath("/bin/bash")
	execArgs := []string{"-c", fmt.Sprintf("%s", scriptFile)}

	cmdImport := &exec.Cmd{
		Path:   psExec,
		Args:   execArgs,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	if noWait {
		return cmdImport.Start()
	}
	return cmdImport.Run()
}

func buildNatsExec(t testing.TB, dirName string) {
	t.Helper()
	startScript := createScriptFile(t, []byte(fmt.Sprintf(`
		cd %s
		go clean
		go build
		`, dirName)))
	err := runBashScript(startScript, nil, false)
	if err != nil {
		t.Fatalf("expected to be able to go build nats-server: %s", err.Error())
	}
}

func killTaskByPID(t testing.TB, imageName string) {
	t.Helper()
	startScript := createScriptFile(t, []byte(fmt.Sprintf(`
PROCESSPID=$(pgrep -f "%s")
kill -9 $PROCESSPID
		`, imageName)))
	err := runBashScript(startScript, nil, false)
	if err != nil {
		t.Fatalf("expected to be able to kill %s: %s", imageName, err.Error())
	}
}

func createNatsService(t testing.TB, svcName string, natsExecFile string, natsConfig string) {
	t.Helper()
	natsConfigFile := createConfFile(t, []byte(natsConfig))
	startScript := createScriptFile(t, []byte(fmt.Sprintf(`
%s --server_name %s --config %s
		`, natsExecFile, svcName, natsConfigFile)))
	err := runBashScript(startScript, nil, true)
	if err != nil {
		t.Fatalf("expected to be able to create and start service: %s", err.Error())
	}
}

func stopNatsService(t testing.TB, svcName string, natsExecFile string) {
	t.Helper()
	startScript := createScriptFile(t, []byte(fmt.Sprintf(`
PROCESSPID=$(pgrep -f "%s")
%s --signal stop=$PROCESSPID
		`, svcName, natsExecFile)))
	err := runBashScript(startScript, nil, false)
	if err != nil {
		t.Fatalf("expected to be able to stop service %s: %s", svcName, err.Error())
	}
}

func TestLinuxServerMetaScenarios(t *testing.T) {
	buildNatsExec(t, "/home/todd/lab/metainf-linux")
	natsExec := "/home/todd/lab/metainf-linux/nats-server"
	jsStateDir := "/home/todd/lab/metainf-linux/jsstate"
	logFile := "/home/todd/lab/metainf-linux/nats-server.log"

	testCases := []struct {
		testName   string
		svcName    string
		svrConfig  string
		jsStateDir string
		logFile    string
	}{
		{
			"Without JS Encryption",
			"nats2",
			`
					port: 4322
					# http_port: 8322
					debug:   false
					# trace:   true
					# logtime: false
					logfile_size_limit: 1GB
					log_file: "%s"
					jetstream: {
						max_memory_store: 1GB
						max_file_store: 2GB
						store_dir: "%s"
						//cipher: "aes"
						//key: "s3cr3ts3cr3ts3cr3ts3cr3ts3cr3ts3"
					}
					accounts: {
						AcctA: {
						  jetstream: enabled
						  users: [ {user: "UserA1", password: "s3cr3t"} ]
						},
						AcctB: {
						  users: [ {user: "UserB1", password: "s3cr3t"} ]
						},
						SYS: {
						  users: [ {user: "System", password: "s3cr3t" } ]
						}
					}
					system_account: "SYS"
				`,
			jsStateDir,
			logFile,
		},
		{
			"With JS Encryption",
			"nats2",
			`
					port: 4322
					# http_port: 8322
					debug:   false
					# trace:   true
					# logtime: false
					logfile_size_limit: 1GB
					log_file: "%s"
					jetstream: {
						max_memory_store: 1GB
						max_file_store: 2GB
						store_dir: "%s"
						cipher: "aes"
						key: "s3cr3ts3cr3ts3cr3ts3cr3ts3cr3ts3"
					}
					accounts: {
						AcctA: {
						  jetstream: enabled
						  users: [ {user: "UserA1", password: "s3cr3t"} ]
						},
						AcctB: {
						  users: [ {user: "UserB1", password: "s3cr3t"} ]
						},
						SYS: {
						  users: [ {user: "System", password: "s3cr3t" } ]
						}
					}
					system_account: "SYS"
				`,
			jsStateDir,
			logFile,
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s", tc.testName), func(t *testing.T) {
			err := os.RemoveAll(jsStateDir + string(os.PathSeparator) + "jetstream")
			if err != nil {
				t.Fatalf("expected to be able to remove jetstream dir: %s", err.Error())
			}
			conf := fmt.Sprintf(tc.svrConfig, tc.logFile, tc.jsStateDir)
			println(conf)
			println("createNatsService...")
			createNatsService(t, tc.svcName, natsExec, conf)
			defer func() {
				println("cleanup... (no op)")
				// killTaskByPID(t, tc.svcName)
			}()
			time.Sleep(5 * time.Second)
			nc, err := nats.Connect("nats://UserA1:s3cr3t@localhost:4322", nil)
			if err != nil {
				t.Errorf("Expected to connect, got %v", err)
			}
			jc, err := nc.JetStream()
			if err != nil {
				t.Errorf("Expected to connect to JetStream, got %v", err)
			}
			// existing stream okay
			strInfo, err := jc.AddStream(&nats.StreamConfig{
				Name:     "foo",
				Subjects: []string{"foo.*"},
				Storage:  nats.FileStorage,
			})
			if err != nil || strInfo == nil {
				t.Errorf("Expected to create stream, got %v", err)
			}
			if strInfo.State.Msgs != 100000 {
				p := make([]byte, 16384)
				_, err := rand.Read(p)
				if err != nil {
					t.Errorf("Expected to generate random bytes, got %v", err)
				}
				for i := 0; i < 100000; i++ {
					ack, err := jc.PublishMsg(&nats.Msg{
						Subject: "foo.bar",
						Data:    p,
					})
					if err != nil || ack == nil {
						t.Errorf("Expected to publish message w/ack, got %v", err)
						break
					}
				}
				time.Sleep(2 * time.Second)
				strInfo, err = jc.StreamInfo("foo")
				if err != nil || strInfo == nil {
					t.Errorf("Expected to get stream info, got %v", err)
				}
				if strInfo.State.Msgs != 100000 {
					t.Errorf("Expected 100000 messages, got %v", strInfo.State.Msgs)
				}
			}
			nc.Close()

			println("stopNatsService... (graceful shutdown)")
			stopNatsService(t, tc.svcName, natsExec)
			time.Sleep(5 * time.Second)
			println("createNatsService 2...")
			createNatsService(t, tc.svcName, natsExec, conf)

			// try to break it
			time.Sleep(500 * time.Millisecond)
			println("killTaskByImageName... (not graceful)")
			killTaskByPID(t, tc.svcName)
			time.Sleep(10 * time.Second)
			println("createNatsService 3...")
			createNatsService(t, tc.svcName, natsExec, conf)
			time.Sleep(10 * time.Second)

			// Did it break?
			nc, err = nats.Connect("nats://UserA1:s3cr3t@localhost:4322", nil)
			if err != nil {
				t.Errorf("Expected to connect, got %v", err)
			}
			jc, err = nc.JetStream()
			if err != nil {
				t.Errorf("Expected to connect to JetStream, got %v", err)
			}
			strInfo, err = jc.StreamInfo("foo")
			if err != nil {
				t.Errorf("Expected to get stream info, got %v", err)
			}
			if strInfo.State.Msgs != 100000 {
				t.Errorf("Expected 100000 messages, got %v", strInfo.State.Msgs)
			}
			nc.Close()
			println("stopNatsService 2...")
			stopNatsService(t, tc.svcName, natsExec)
			time.Sleep(5 * time.Second)
		})
	}
}
