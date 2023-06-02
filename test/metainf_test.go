//go:build windows

package test

import (
	"fmt"
	"github.com/nats-io/nats.go"
	"math/rand"
	"os"
	"os/exec"
	"testing"
	"time"
)

func createPS1File(t testing.TB, content []byte) string {
	t.Helper()
	script, err := os.CreateTemp(t.TempDir(), "script-*.ps1")
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

func runPowershellScript(scriptFile string, args []string) error {
	_ = args
	psExec, _ := exec.LookPath("powershell.exe")
	execArgs := []string{psExec, "-command", fmt.Sprintf("& '%s'", scriptFile)}

	cmdImport := &exec.Cmd{
		Path:   psExec,
		Args:   execArgs,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	return cmdImport.Run()
}

func buildNatsExec(t testing.TB, dirName string) {
	t.Helper()
	startScript := createPS1File(t, []byte(fmt.Sprintf(`
		cd %s
		go clean
		go build
		`, dirName)))
	err := runPowershellScript(startScript, nil)
	if err != nil {
		t.Fatalf("expected to be able to go build nats-server.exe: %s", err.Error())
	}
}

func killTaskByImageName(t testing.TB, imageName string) {
	t.Helper()
	startScript := createPS1File(t, []byte(fmt.Sprintf(`
		taskkill /IM "%s" /T /F
		`, imageName)))
	err := runPowershellScript(startScript, nil)
	if err != nil {
		t.Fatalf("expected to be able to taskkill %s: %s", imageName, err.Error())
	}
}

func startNatsService(t testing.TB, svcName string) {
	t.Helper()
	startScript := createPS1File(t, []byte(fmt.Sprintf(`
		# Must be run as Administrator
		$svcName = "%s"
		sc.exe start $svcName
		`, svcName)))
	err := runPowershellScript(startScript, nil)
	if err != nil {
		t.Fatalf("expected to be able to start service: %s", err.Error())
	}
}

func createNatsService(t testing.TB, svcName string, natsExecFile string, natsConfig string) {
	t.Helper()
	natsConfigFile := createConfFile(t, []byte(natsConfig))
	startScript := createPS1File(t, []byte(fmt.Sprintf(`
		# Must be run as Administrator
		$svcName = "%s"
		$natsExec = "%s"
		$natsConfig = "%s"
		sc.exe create $svcName binPath= "$natsExec -c $natsConfig" DisplayName= "NATS Server" start= demand
		sc.exe start $svcName
		`, svcName, natsExecFile, natsConfigFile)))
	err := runPowershellScript(startScript, nil)
	if err != nil {
		t.Fatalf("expected to be able to create and start service: %s", err.Error())
	}
}

func stopNatsService(t testing.TB, svcName string) {
	t.Helper()
	startScript := createPS1File(t, []byte(fmt.Sprintf(`
		# Must be run as Administrator
		$svcName = "%s"
		sc.exe stop $svcName
		`, svcName)))
	err := runPowershellScript(startScript, nil)
	if err != nil {
		t.Fatalf("expected to be able to stop service: %s", err.Error())
	}
}

func deleteNatsService(t testing.TB, svcName string) {
	t.Helper()
	startScript := createPS1File(t, []byte(fmt.Sprintf(`
		# Must be run as Administrator
		$svcName = "%s"
		sc.exe delete $svcName
		`, svcName)))
	err := runPowershellScript(startScript, nil)
	if err != nil {
		t.Fatalf("expected to be able to stop and delete service: %s", err.Error())
	}
}

//func TestManipWindowsService(t *testing.T) {
//	confStr := `
//		port: 4322
//		server_name: shortlife
//		`
//	natsExec := "C:\\Users\\todd\\lab\\metainf-windows\\nats-server.exe"
//	buildNatsExec(t, "C:\\Users\\todd\\lab\\metainf-windows")
//	createNatsService(t, "natsshortlife", natsExec, confStr)
//	stopNatsService(t, "natsshortlife")
//	startNatsService(t, "natsshortlife")
//	killTaskByImageName(t, "nats-server.exe")
//	deleteNatsService(t, "natsshortlife")
//}

func TestWindowsServerMetaScenarios(t *testing.T) {
	buildNatsExec(t, "C:\\Users\\todd\\lab\\metainf-windows")
	natsExec := "C:\\Users\\todd\\lab\\metainf-windows\\nats-server.exe"
	jsStateDir := "C:/Users/todd/lab/metainf-windows/jsstate"
	logFile := "C:/Users/todd/lab/metainf-windows/nats-server.log"

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
				println("deleteNatsService...")
				deleteNatsService(t, tc.svcName)
			}()
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

			println("stopNatsService...")
			stopNatsService(t, tc.svcName)
			time.Sleep(5 * time.Second)
			println("startNatsService 1...")
			startNatsService(t, tc.svcName)

			// try to break it
			time.Sleep(500 * time.Millisecond)
			println("killTaskByImageName...")
			killTaskByImageName(t, "nats-server.exe")
			time.Sleep(10 * time.Second)
			println("startNatsService 2...")
			startNatsService(t, tc.svcName)
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
			stopNatsService(t, tc.svcName)
			time.Sleep(5 * time.Second)
		})
	}
}
