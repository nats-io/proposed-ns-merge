package server

import (
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

type snapServerSubs struct {
	serverName string
	accs       []*snapAccountSubs
}

type snapAccountSubs struct {
	accName string
	subs    []*snapSub
}

type snapSub struct {
	subType string
	subject []byte
	kind    string
	isSpoke bool
	sid     []byte
	queue   []byte
	qw      int32
}

func stringifyKind(kindNum int) string {
	switch kindNum {
	case 0:
		return "CLIENT"
	case 1:
		return "ROUTER"
	case 2:
		return "GATEWAY"
	case 3:
		return "SYSTEM"
	case 4:
		return "LEAF"
	case 5:
		return "JETSTREAM"
	case 6:
		return "ACCOUNT"
	default:
		return "UNKNOWN"
	}
}

func snapSubsExist(snap *snapServerSubs) bool {
	if snap == nil || len(snap.accs) == 0 {
		return false
	}
	for _, acc := range snap.accs {
		if len(acc.subs) > 0 {
			return true
		}
	}
	return false
}

func doSnapSubzForSubjectOnCluster(c *cluster, subject string, accNames []string, log bool) []*snapServerSubs {
	if len(accNames) == 0 || subject == "" || c == nil {
		return nil
	}
	var cSnap []*snapServerSubs
	i1 := ""
	if log {
		println(i1, "cluster:", c.name)
	}
	for _, s := range c.servers {
		snap := doSnapSubzForSubjectOnServer(s, subject, accNames, log)
		if snap != nil {
			cSnap = append(cSnap, snap)
		}
	}
	return cSnap
}

func doSnapServerSubs(s *Server, subject string, accNames []string) *snapServerSubs {
	if len(accNames) == 0 || subject == "" || s == nil {
		return nil
	}
	snap := &snapServerSubs{serverName: s.Name()}
	for _, accName := range accNames {
		acc, err := s.LookupAccount(accName)
		if err != nil {
			continue
		}
		accSnap := &snapAccountSubs{accName: acc.Name}
		sl := acc.sl.Match(subject)
		if sl != nil {
			for _, psub := range sl.psubs {
				snapSub := &snapSub{
					subType: "psub",
					subject: psub.subject,
					kind:    stringifyKind(psub.client.kind),
					isSpoke: psub.client.isSpokeLeafNode(),
					sid:     psub.sid,
				}
				accSnap.subs = append(accSnap.subs, snapSub)
			}
			for _, qsubs := range sl.qsubs {
				for _, qsub := range qsubs {
					snapSub := &snapSub{
						subType: "qsub",
						subject: qsub.subject,
						kind:    stringifyKind(qsub.client.kind),
						isSpoke: qsub.client.isSpokeLeafNode(),
						sid:     qsub.sid,
						queue:   qsub.queue,
						qw:      qsub.qw,
					}
					accSnap.subs = append(accSnap.subs, snapSub)
				}
			}
		}
		snap.accs = append(snap.accs, accSnap)
	}
	return snap
}

func doSnapSubzForSubjectOnServer(s *Server, subject string, accNames []string, log bool) *snapServerSubs {
	if len(accNames) == 0 || subject == "" || s == nil {
		return nil
	}
	i1 := "\t"
	i2 := "\t\t"
	// i3 := "\t\t\t"
	i4 := "\t\t\t\t"
	if log {
		println(i1, "server:", s.Name())
	}
	snap := doSnapServerSubs(s, subject, accNames)
	if snap == nil {
		return nil
	}
	if log {
		for _, acc := range snap.accs {
			println(i2, "account:", acc.accName)
			for _, sub := range acc.subs {
				if sub.subType != "psub" {
					continue
				}
				println(i4, "psub kind:", sub.kind, i2, "sid:", string(sub.sid), "isSpoke:", sub.isSpoke)
			}
			for _, sub := range acc.subs {
				if sub.subType != "qsub" {
					continue
				}
				println(i4, "qsub kind:", sub.kind, i1, "qw:", sub.qw, i1, "queue:", string(sub.queue), i2, "sid:", string(sub.sid), "isSpoke:", sub.isSpoke)
			}
		}
	}
	return snap
}

func TestLeafNodeWithWeightedDQRequestsToSuperClusterWithStreamImportAccounts2(t *testing.T) {
	var tmpl = `
	listen: 127.0.0.1:-1

	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf { listen: 127.0.0.1:-1 }

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {
		EFG {
			users = [ { user: "efg", pass: "p" } ]
			jetstream: enabled
			imports [
				{ stream: { account: STL, subject: "REQUEST"} }
				{ stream: { account: KSC, subject: "REQUEST"} }
			]
			exports [ { stream: "RESPONSE" } ]
		}
		STL {
			users = [ { user: "stl", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		KSC {
			users = [ { user: "ksc", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}`

	sc := createJetStreamSuperClusterWithTemplate(t, tmpl, 3, 2)
	defer sc.shutdown()

	// Now create a leafnode cluster that has 2 LNs, one to each cluster but on separate accounts, ONE and TWO.
	var lnTmpl = `
		listen: 127.0.0.1:-1
		server_name: %s
		jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

		{{leaf}}

		cluster {
			name: %s
			listen: 127.0.0.1:%d
			routes = [%s]
		}

		accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }}
		`

	var leafFrag = `
		leaf {
			listen: 127.0.0.1:-1
			remotes [
				{ urls: [ %s ] }
				{ urls: [ %s ] }
				{ urls: [ %s ] ; deny_export: [REQUEST, RESPONSE], deny_import: RESPONSE }
			]
		}`

	// We want to have two leaf node connections that join to the same local account on the leafnode servers,
	// but connect to different accounts in different clusters.
	c1 := sc.clusters[0] // Will connect to account KSC
	c2 := sc.clusters[1] // Will connect to account STL

	genLeafTmpl := func(tmpl string) string {
		t.Helper()

		var ln1, ln2, ln3 []string
		for _, s := range c1.servers {
			if s.ClusterName() != c1.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln1 = append(ln1, fmt.Sprintf("nats://ksc:p@%s:%d", ln.Host, ln.Port))
		}

		for _, s := range c2.servers {
			if s.ClusterName() != c2.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln2 = append(ln2, fmt.Sprintf("nats://stl:p@%s:%d", ln.Host, ln.Port))
			ln3 = append(ln3, fmt.Sprintf("nats://efg:p@%s:%d", ln.Host, ln.Port))
		}
		return strings.Replace(tmpl, "{{leaf}}", fmt.Sprintf(leafFrag, strings.Join(ln1, ", "), strings.Join(ln2, ", "), strings.Join(ln3, ", ")), 1)
	}

	tmpl = strings.Replace(lnTmpl, "store_dir:", fmt.Sprintf(`domain: "%s", store_dir:`, "SA"), 1)
	tmpl = genLeafTmpl(tmpl)

	ln := createJetStreamCluster(t, tmpl, "SA", "SA-", 3, 22280, false)
	ln.waitOnClusterReady()
	defer ln.shutdown()

	for _, s := range ln.servers {
		checkLeafNodeConnectedCount(t, s, 3)
	}

	// Now connect DQ subscribers to each cluster but to the global account.

	// Create 5 clients for each cluster / account
	var c1c, c2c []*nats.Conn
	for i := 0; i < 5; i++ {
		nc1, _ := jsClientConnect(t, c1.randomServer(), nats.UserInfo("efg", "p"))
		defer nc1.Close()
		c1c = append(c1c, nc1)
		nc2, _ := jsClientConnect(t, c2.randomServer(), nats.UserInfo("efg", "p"))
		defer nc2.Close()
		c2c = append(c2c, nc2)
	}

	createSubs := func(num int, conns []*nats.Conn) (subs []*nats.Subscription) {
		for i := 0; i < num; i++ {
			nc := conns[rand.Intn(len(conns))]
			sub, err := nc.QueueSubscribeSync("REQUEST", "MC")
			require_NoError(t, err)
			subs = append(subs, sub)
			nc.Flush()
		}
		// Let subs propagate.
		time.Sleep(100 * time.Millisecond)
		return subs
	}
	closeSubs := func(subs []*nats.Subscription) {
		for _, sub := range subs {
			sub.Unsubscribe()
		}
	}

	// Simple test first.
	subs1 := createSubs(1, c1c)
	defer closeSubs(subs1)
	subs2 := createSubs(1, c2c)
	defer closeSubs(subs2)

	sendRequests := func(num int) {
		t.Helper()
		// Now connect to the leaf cluster and send some requests.
		nc, _ := jsClientConnect(t, ln.randomServer())
		defer nc.Close()

		for i := 0; i < num; i++ {
			require_NoError(t, nc.Publish("REQUEST", []byte("HELP")))
		}
		nc.Flush()
	}

	pending := func(subs []*nats.Subscription) (total int) {
		t.Helper()
		for _, sub := range subs {
			n, _, err := sub.Pending()
			require_NoError(t, err)
			total += n
		}
		return total
	}

	num := 1000
	checkAllReceived := func() error {
		total := pending(subs1) + pending(subs2)
		if total == num {
			return nil
		}
		return fmt.Errorf("Not all received: %d vs %d", total, num)
	}

	checkBalanced := func(total, pc1, pc2 int) {
		t.Helper()
		tf := float64(total)
		e1 := tf * (float64(pc1) / 100.00)
		e2 := tf * (float64(pc2) / 100.00)
		delta := tf / 10
		p1 := float64(pending(subs1))
		if p1 < e1-delta || p1 > e1+delta {
			t.Fatalf("Value out of range for subs1, expected %v got %v", e1, p1)
		}
		p2 := float64(pending(subs2))
		if p2 < e2-delta || p2 > e2+delta {
			t.Fatalf("Value out of range for subs2, expected %v got %v", e2, p2)
		}
	}

	// Now connect to the leaf cluster and send some requests.

	// Simple 50/50
	sendRequests(num)
	checkFor(t, time.Second, 200*time.Millisecond, checkAllReceived)
	checkBalanced(num, 50, 50)

	closeSubs(subs1)
	closeSubs(subs2)

	// Now test unbalanced. 10/90
	subs1 = createSubs(1, c1c)
	defer closeSubs(subs1)
	subs2 = createSubs(9, c2c)
	defer closeSubs(subs2)

	sendRequests(num)
	checkFor(t, time.Second, 200*time.Millisecond, checkAllReceived)
	checkBalanced(num, 10, 90)

	closeSubs(subs1)
	closeSubs(subs2)

	// Now test unbalanced. 80/20
	subs1 = createSubs(80, c1c)
	defer closeSubs(subs1)
	subs2 = createSubs(20, c2c)
	defer closeSubs(subs2)

	sendRequests(num)
	checkFor(t, time.Second, 200*time.Millisecond, checkAllReceived)
	checkBalanced(num, 80, 20)

	// Now test draining the subs as we are sending from an initial balanced situation simulating a draining of a cluster.

	closeSubs(subs1)
	closeSubs(subs2)
	subs1, subs2 = nil, nil

	// These subs slightly different.
	var r1, r2 atomic.Uint64
	for i := 0; i < 20; i++ {
		nc := c1c[rand.Intn(len(c1c))]
		sub, err := nc.QueueSubscribe("REQUEST", "MC", func(m *nats.Msg) { r1.Add(1) })
		require_NoError(t, err)
		subs1 = append(subs1, sub)
		nc.Flush()

		nc = c2c[rand.Intn(len(c2c))]
		sub, err = nc.QueueSubscribe("REQUEST", "MC", func(m *nats.Msg) { r2.Add(1) })
		require_NoError(t, err)
		subs2 = append(subs2, sub)
		nc.Flush()
	}
	defer closeSubs(subs1)
	defer closeSubs(subs2)

	nc, _ := jsClientConnect(t, ln.randomServer())
	defer nc.Close()

	for i, dindex := 0, 1; i < num; i++ {
		require_NoError(t, nc.Publish("REQUEST", []byte("HELP")))
		// Check if we have more to simulate draining.
		// Will drain within first ~100 requests using 20% rand test below.
		// Will leave 1 behind.
		if dindex < len(subs1)-1 && rand.Intn(6) > 4 {
			sub := subs1[dindex]
			dindex++
			sub.Drain()
		}
	}
	nc.Flush()

	checkFor(t, time.Second, 200*time.Millisecond, func() error {
		total := int(r1.Load() + r2.Load())
		if total == num {
			return nil
		}
		return fmt.Errorf("Not all received: %d vs %d", total, num)
	})
	require_True(t, r2.Load() > r1.Load())

	// Now check opposite flow for responses.

	// Create 10 subscribers.
	var rsubs []*nats.Subscription

	for i := 0; i < 10; i++ {
		nc, _ := jsClientConnect(t, ln.randomServer())
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA")
		require_NoError(t, err)
		nc.Flush()
		rsubs = append(rsubs, sub)
	}

	// Create a second unique DQ with 10 additional subscribers.
	var rsubs2 = []*nats.Subscription{}

	for i := 0; i < 10; i++ {
		nc, _ := jsClientConnect(t, ln.randomServer())
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA2")
		require_NoError(t, err)
		nc.Flush()
		rsubs2 = append(rsubs2, sub)
	}

	nc, _ = jsClientConnect(t, ln.randomServer())
	defer nc.Close()
	_, err := nc.SubscribeSync("RESPONSE")
	require_NoError(t, err)
	nc.Flush()

	// sub propogation
	time.Sleep(1 * time.Second)

	// Now connect and send responses from EFG in cloud.
	nc, _ = jsClientConnect(t, sc.randomServer(), nats.UserInfo("efg", "p"))

	for i := 0; i < 100; i++ {
		require_NoError(t, nc.Publish("RESPONSE", []byte("OK")))
	}
	nc.Flush()

	checkAllRespReceived := func() error {
		p := pending(rsubs)
		if p == 100 {
			t.Logf("All responses received by SA DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA DQ: %d vs %d", p, 100)
	}

	checkAllRespReceived2 := func() error {
		p := pending(rsubs2)
		if p == 100 {
			t.Logf("All responses received by SA2 DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA2 DQ: %d vs %d", p, 100)
	}

	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived2)
	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived)

	// Now remove all the subscriptions and re-check sub propogration state
	for _, sub := range rsubs {
		sub.Unsubscribe()
	}
	for _, sub := range rsubs2 {
		sub.Unsubscribe()
	}

	time.Sleep(2 * time.Second)
	// println("FINAL State of KSC+STL clusters")
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
		for _, snap := range cSnap {
			require_True(t, !snapSubsExist(snap))
		}
	}
}

func TestLeafNodeMCConfigDownlinkOnly3Remotes(t *testing.T) {
	var tmpl = `
	listen: 127.0.0.1:-1

	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf { listen: 127.0.0.1:-1 }

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {
		EFG {
			users = [ { user: "efg", pass: "p" } ]
			jetstream: enabled
			imports [
				{ stream: { account: STL, subject: "REQUEST"} }
				{ stream: { account: KSC, subject: "REQUEST"} }
			]
			exports [ { stream: "RESPONSE" } ]
		}
		STL {
			users = [ { user: "stl", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		KSC {
			users = [ { user: "ksc", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}`

	sc := createJetStreamSuperClusterWithTemplate(t, tmpl, 3, 2)
	defer sc.shutdown()

	// Now create a leafnode cluster that has 2 LNs, one to each cluster but on separate accounts, ONE and TWO.
	var lnTmpl = `
		listen: 127.0.0.1:-1
		server_name: %s
		jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

		{{leaf}}

		cluster {
			name: %s
			listen: 127.0.0.1:%d
			routes = [%s]
		}

		accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }}
		`

	var leafFrag = `
		leaf {
			listen: 127.0.0.1:-1
			remotes [
				{ urls: [ %s ] }
				{ urls: [ %s ] }
				{ urls: [ %s ] ; deny_export: [REQUEST, RESPONSE], deny_import: RESPONSE }
			]
		}`

	// We want to have two leaf node connections that join to the same local account on the leafnode servers,
	// but connect to different accounts in different clusters.
	c1 := sc.clusters[0] // Will connect to account KSC
	c2 := sc.clusters[1] // Will connect to account STL

	genLeafTmpl := func(tmpl string) string {
		t.Helper()

		var ln1, ln2, ln3 []string
		for _, s := range c1.servers {
			if s.ClusterName() != c1.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln1 = append(ln1, fmt.Sprintf("nats://ksc:p@%s:%d", ln.Host, ln.Port))
		}

		for _, s := range c2.servers {
			if s.ClusterName() != c2.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln2 = append(ln2, fmt.Sprintf("nats://stl:p@%s:%d", ln.Host, ln.Port))
			ln3 = append(ln3, fmt.Sprintf("nats://efg:p@%s:%d", ln.Host, ln.Port))
		}
		return strings.Replace(tmpl, "{{leaf}}", fmt.Sprintf(leafFrag, strings.Join(ln1, ", "), strings.Join(ln2, ", "), strings.Join(ln3, ", ")), 1)
	}

	tmpl = strings.Replace(lnTmpl, "store_dir:", fmt.Sprintf(`domain: "%s", store_dir:`, "SA"), 1)
	tmpl = genLeafTmpl(tmpl)

	ln := createJetStreamCluster(t, tmpl, "SA", "SA-", 3, 22280, false)
	ln.waitOnClusterReady()
	defer ln.shutdown()

	for _, s := range ln.servers {
		checkLeafNodeConnectedCount(t, s, 3)
	}

	// Now connect DQ subscribers to each cluster but to the global account.

	// Create 5 clients for each cluster / account
	var c1c, c2c []*nats.Conn
	for i := 0; i < 5; i++ {
		nc1, _ := jsClientConnect(t, c1.randomServer(), nats.UserInfo("efg", "p"))
		defer nc1.Close()
		c1c = append(c1c, nc1)
		nc2, _ := jsClientConnect(t, c2.randomServer(), nats.UserInfo("efg", "p"))
		defer nc2.Close()
		c2c = append(c2c, nc2)
	}

	pending := func(subs []*nats.Subscription) (total int) {
		t.Helper()
		for _, sub := range subs {
			n, _, err := sub.Pending()
			require_NoError(t, err)
			total += n
		}
		return total
	}

	// Create 10 subscribers.
	var rsubs []*nats.Subscription

	for i := 0; i < 10; i++ {
		nc, _ := jsClientConnect(t, ln.randomServer())
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA")
		require_NoError(t, err)
		nc.Flush()
		rsubs = append(rsubs, sub)
	}

	// Create a second unique DQ with 10 additional subscribers.
	var rsubs2 = []*nats.Subscription{}

	for i := 0; i < 10; i++ {
		nc, _ := jsClientConnect(t, ln.randomServer())
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA2")
		require_NoError(t, err)
		nc.Flush()
		rsubs2 = append(rsubs2, sub)
	}

	nc, _ := jsClientConnect(t, ln.randomServer())
	defer nc.Close()
	_, err := nc.SubscribeSync("RESPONSE")
	require_NoError(t, err)
	nc.Flush()

	// sub propogation
	time.Sleep(1 * time.Second)

	// Now connect and send responses from EFG in cloud.
	nc, _ = jsClientConnect(t, sc.randomServer(), nats.UserInfo("efg", "p"))
	defer nc.Close()

	for i := 0; i < 100; i++ {
		require_NoError(t, nc.Publish("RESPONSE", []byte("OK")))
	}
	nc.Flush()

	checkAllRespReceived := func() error {
		p := pending(rsubs)
		if p == 100 {
			t.Logf("All responses received by SA DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA DQ: %d vs %d", p, 100)
	}

	checkAllRespReceived2 := func() error {
		p := pending(rsubs2)
		if p == 100 {
			t.Logf("All responses received by SA2 DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA2 DQ: %d vs %d", p, 100)
	}

	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived2)
	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived)

	println("State of KSC+STL clusters")
	for _, c := range sc.clusters {
		_ = doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
	}

	println("State of SA cluster")
	_ = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, true)
}

func TestLeafNodeMCConfigDownlinkOnly2Remotes(t *testing.T) {
	var tmpl = `
	listen: 127.0.0.1:-1

	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf { listen: 127.0.0.1:-1 }

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {
		EFG {
			users = [ { user: "efg", pass: "p" } ]
			jetstream: enabled
			imports [
				{ stream: { account: STL, subject: "REQUEST"} }
				{ stream: { account: KSC, subject: "REQUEST"} }
			]
			exports [ { stream: "RESPONSE" } ]
		}
		STL {
			users = [ { user: "stl", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		KSC {
			users = [ { user: "ksc", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}`

	sc := createJetStreamSuperClusterWithTemplate(t, tmpl, 3, 2)
	defer sc.shutdown()

	// Now create a leafnode cluster that has 2 LNs, one to each cluster but on separate accounts, ONE and TWO.
	var lnTmpl = `
		listen: 127.0.0.1:-1
		server_name: %s
		jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

		{{leaf}}

		cluster {
			name: %s
			listen: 127.0.0.1:%d
			routes = [%s]
		}

		accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }}
		`

	var leafFrag = `
		leaf {
			listen: 127.0.0.1:-1
			remotes [
				{ urls: [ %s ] }
				{ urls: [ %s ] }
			]
		}`

	// We want to have two leaf node connections that join to the same local account on the leafnode servers,
	// but connect to different accounts in different clusters.
	c1 := sc.clusters[0] // Will connect to account KSC
	c2 := sc.clusters[1] // Will connect to account STL

	genLeafTmpl := func(tmpl string) string {
		t.Helper()

		var ln1, ln2 []string
		for _, s := range c1.servers {
			if s.ClusterName() != c1.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln1 = append(ln1, fmt.Sprintf("nats://ksc:p@%s:%d", ln.Host, ln.Port))
		}

		for _, s := range c2.servers {
			if s.ClusterName() != c2.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln2 = append(ln2, fmt.Sprintf("nats://stl:p@%s:%d", ln.Host, ln.Port))
		}
		return strings.Replace(tmpl, "{{leaf}}", fmt.Sprintf(leafFrag, strings.Join(ln1, ", "), strings.Join(ln2, ", ")), 1)
	}

	tmpl = strings.Replace(lnTmpl, "store_dir:", fmt.Sprintf(`domain: "%s", store_dir:`, "SA"), 1)
	tmpl = genLeafTmpl(tmpl)

	ln := createJetStreamCluster(t, tmpl, "SA", "SA-", 3, 22280, false)
	ln.waitOnClusterReady()
	defer ln.shutdown()

	for _, s := range ln.servers {
		checkLeafNodeConnectedCount(t, s, 2)
	}

	// Now connect DQ subscribers to each cluster but to the global account.

	// Create 5 clients for each cluster / account
	var c1c, c2c []*nats.Conn
	for i := 0; i < 5; i++ {
		nc1, _ := jsClientConnect(t, c1.randomServer(), nats.UserInfo("efg", "p"))
		defer nc1.Close()
		c1c = append(c1c, nc1)
		nc2, _ := jsClientConnect(t, c2.randomServer(), nats.UserInfo("efg", "p"))
		defer nc2.Close()
		c2c = append(c2c, nc2)
	}

	pending := func(subs []*nats.Subscription) (total int) {
		t.Helper()
		for _, sub := range subs {
			n, _, err := sub.Pending()
			require_NoError(t, err)
			total += n
		}
		return total
	}

	// Create 10 subscribers.
	var rsubs []*nats.Subscription

	for i := 0; i < 3; i++ {
		nc, _ := jsClientConnect(t, ln.randomServer())
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA")
		require_NoError(t, err)
		nc.Flush()
		rsubs = append(rsubs, sub)
	}

	// Create a second unique DQ with 10 additional subscribers.
	var rsubs2 = []*nats.Subscription{}

	for i := 0; i < 3; i++ {
		nc, _ := jsClientConnect(t, ln.randomServer())
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA2")
		require_NoError(t, err)
		nc.Flush()
		rsubs2 = append(rsubs2, sub)
	}

	//nc, _ := jsClientConnect(t, ln.randomServer())
	//defer nc.Close()
	//_, err := nc.SubscribeSync("RESPONSE")
	//require_NoError(t, err)
	//nc.Flush()

	// sub propogation
	time.Sleep(1 * time.Second)

	// Now connect and send responses from EFG in cloud.
	rando := sc.randomServer()
	// println("RESPONSE publisher rando is", rando.Name())
	nc, _ := jsClientConnect(t, rando, nats.UserInfo("efg", "p"))
	defer nc.Close()

	for i := 0; i < 100; i++ {
		require_NoError(t, nc.Publish("RESPONSE", []byte("OK")))
	}
	nc.Flush()

	checkAllRespReceived := func() error {
		p := pending(rsubs)
		if p == 100 {
			t.Logf("All responses received by SA DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA DQ: %d vs %d", p, 100)
	}

	checkAllRespReceived2 := func() error {
		p := pending(rsubs2)
		if p == 100 {
			t.Logf("All responses received by SA2 DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA2 DQ: %d vs %d", p, 100)
	}

	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived2)
	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived)

	println("State of KSC+STL clusters")
	for _, c := range sc.clusters {
		_ = doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
	}

	println("State of SA cluster")
	_ = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, true)

	// Now remove all the subscriptions and re-check sub propogration state
	for _, sub := range rsubs {
		sub.Unsubscribe()
	}
	for _, sub := range rsubs2 {
		sub.Unsubscribe()
	}

	time.Sleep(2 * time.Second)
	// println("FINAL State of KSC+STL clusters")
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, false)
		for _, snap := range cSnap {
			require_True(t, !snapSubsExist(snap))
		}
	}

	// println("FINAL State of SA cluster")
	cSnap := doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, false)
	for _, snap := range cSnap {
		require_True(t, !snapSubsExist(snap))
	}
}

func TestLeafNodeMCConfigDownlinkOnlyOneLeafAcctRandom(t *testing.T) {
	var tmpl = `
	listen: 127.0.0.1:-1

	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf { listen: 127.0.0.1:-1 }

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {
		EFG {
			users = [ { user: "efg", pass: "p" } ]
			jetstream: enabled
			imports [
				{ stream: { account: STL, subject: "REQUEST"} }
				{ stream: { account: KSC, subject: "REQUEST"} }
			]
			exports [ { stream: "RESPONSE" } ]
		}
		STL {
			users = [ { user: "stl", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		KSC {
			users = [ { user: "ksc", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}`

	sc := createJetStreamSuperClusterWithTemplate(t, tmpl, 3, 2)
	defer sc.shutdown()

	// Now create a leafnode cluster that has 2 LNs, one to each cluster but on separate accounts, ONE and TWO.
	var lnTmpl = `
		listen: 127.0.0.1:-1
		server_name: %s
		jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

		{{leaf}}

		cluster {
			name: %s
			listen: 127.0.0.1:%d
			routes = [%s]
		}

		accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }}
		`

	var leafFrag = `
		leaf {
			listen: 127.0.0.1:-1
			remotes [
				{ urls: [ %s ] }
			]
		}`

	// We want to have two leaf node connections that join to the same local account on the leafnode servers,
	// but connect to different accounts in different clusters.
	c1 := sc.clusters[0] // Will connect to account KSC
	c2 := sc.clusters[1] // Will connect to account STL

	genLeafTmpl := func(tmpl string) string {
		t.Helper()

		var ln1 []string
		for _, s := range c1.servers {
			if s.ClusterName() != c1.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln1 = append(ln1, fmt.Sprintf("nats://ksc:p@%s:%d", ln.Host, ln.Port))
		}

		// Only have SA cluster nodes leaf connect to KSC cluster as ksc user.
		return strings.Replace(tmpl, "{{leaf}}", fmt.Sprintf(leafFrag, strings.Join(ln1, ", ")), 1)
	}

	tmpl = strings.Replace(lnTmpl, "store_dir:", fmt.Sprintf(`domain: "%s", store_dir:`, "SA"), 1)
	tmpl = genLeafTmpl(tmpl)

	ln := createJetStreamCluster(t, tmpl, "SA", "SA-", 3, 22280, false)
	ln.waitOnClusterReady()
	defer ln.shutdown()

	for _, s := range ln.servers {
		checkLeafNodeConnectedCount(t, s, 1)
	}

	// Now connect DQ subscribers to each cluster but to the global account.

	// Create 5 clients for each cluster / account
	var c1c, c2c []*nats.Conn
	for i := 0; i < 5; i++ {
		nc1, _ := jsClientConnect(t, c1.randomServer(), nats.UserInfo("efg", "p"))
		defer nc1.Close()
		c1c = append(c1c, nc1)
		nc2, _ := jsClientConnect(t, c2.randomServer(), nats.UserInfo("efg", "p"))
		defer nc2.Close()
		c2c = append(c2c, nc2)
	}

	pending := func(subs []*nats.Subscription) (total int) {
		t.Helper()
		for _, sub := range subs {
			n, _, err := sub.Pending()
			require_NoError(t, err)
			total += n
		}
		return total
	}

	// Make sure no subs to start test
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, false)
		require_True(t, cSnap != nil && len(cSnap) != 0)
		for _, snap := range cSnap {
			require_True(t, snap != nil && !snapSubsExist(snap))
		}
	}
	cSnap := doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, false)
	require_True(t, cSnap != nil && len(cSnap) != 0)
	for _, snap := range cSnap {
		require_True(t, snap != nil && !snapSubsExist(snap))
	}

	// Create Spoke subscribers.
	var rsubs []*nats.Subscription

	for i := 0; i < 2; i++ {
		nc, _ := jsClientConnect(t, ln.randomServer())
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA")
		require_NoError(t, err)
		nc.Flush()
		rsubs = append(rsubs, sub)
	}

	// Create a second unique DQ with 10 additional subscribers.
	var rsubs2 = []*nats.Subscription{}

	for i := 0; i < 0; i++ {
		nc, _ := jsClientConnect(t, ln.randomServer())
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA2")
		require_NoError(t, err)
		nc.Flush()
		rsubs2 = append(rsubs2, sub)
	}

	// sub propogation
	time.Sleep(1 * time.Second)

	// Now connect and send responses from EFG in cloud.
	rando := sc.randomServer()
	// println("RESPONSE publisher rando is", rando.Name())
	nc, _ := jsClientConnect(t, rando, nats.UserInfo("efg", "p"))
	defer nc.Close()

	for i := 0; i < 100; i++ {
		require_NoError(t, nc.Publish("RESPONSE", []byte("OK")))
	}
	nc.Flush()

	checkAllRespReceived := func() error {
		p := pending(rsubs)
		if p == 100 {
			t.Logf("All responses received by SA DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA DQ: %d vs %d", p, 100)
	}

	checkAllRespReceived2 := func() error {
		p := pending(rsubs2)
		if p <= 0 {
			t.Logf("All responses received by SA2 DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA2 DQ: %d vs %d", p, 100)
	}

	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived2)
	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived)

	time.Sleep(2 * time.Second)
	println("State of KSC+STL clusters")
	for _, c := range sc.clusters {
		_ = doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
	}

	println("State of SA cluster")
	_ = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, true)

	// Now remove all the subscriptions and re-check sub propogration state
	for _, sub := range rsubs {
		sub.Unsubscribe()
	}
	for _, sub := range rsubs2 {
		sub.Unsubscribe()
	}

	time.Sleep(4 * time.Second)
	// println("FINAL State of KSC+STL clusters")
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
		for _, snap := range cSnap {
			require_True(t, !snapSubsExist(snap))
		}
	}

	// println("FINAL State of SA cluster")
	cSnap = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, false)
	for _, snap := range cSnap {
		require_True(t, !snapSubsExist(snap))
	}
}

// This test always passes as we spread leaf subscribers to their own spoke node
func TestLeafNodeMCConfigDownlinkOnlyOneLeafAcctAlwaysSpread(t *testing.T) {
	var tmpl = `
	listen: 127.0.0.1:-1

	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf { listen: 127.0.0.1:-1 }

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {
		EFG {
			users = [ { user: "efg", pass: "p" } ]
			jetstream: enabled
			imports [
				{ stream: { account: STL, subject: "REQUEST"} }
				{ stream: { account: KSC, subject: "REQUEST"} }
			]
			exports [ { stream: "RESPONSE" } ]
		}
		STL {
			users = [ { user: "stl", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		KSC {
			users = [ { user: "ksc", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}`

	sc := createJetStreamSuperClusterWithTemplate(t, tmpl, 3, 2)
	defer sc.shutdown()

	// Now create a leafnode cluster that has 2 LNs, one to each cluster but on separate accounts, ONE and TWO.
	var lnTmpl = `
		listen: 127.0.0.1:-1
		server_name: %s
		jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

		{{leaf}}

		cluster {
			name: %s
			listen: 127.0.0.1:%d
			routes = [%s]
		}

		accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }}
		`

	var leafFrag = `
		leaf {
			listen: 127.0.0.1:-1
			remotes [
				{ urls: [ %s ] }
			]
		}`

	// We want to have two leaf node connections that join to the same local account on the leafnode servers,
	// but connect to different accounts in different clusters.
	c1 := sc.clusters[0] // Will connect to account KSC
	c2 := sc.clusters[1] // Will connect to account STL

	genLeafTmpl := func(tmpl string) string {
		t.Helper()

		var ln1 []string
		for _, s := range c1.servers {
			if s.ClusterName() != c1.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln1 = append(ln1, fmt.Sprintf("nats://ksc:p@%s:%d", ln.Host, ln.Port))
		}

		// Only have SA cluster nodes leaf connect to KSC cluster as ksc user.
		return strings.Replace(tmpl, "{{leaf}}", fmt.Sprintf(leafFrag, strings.Join(ln1, ", ")), 1)
	}

	tmpl = strings.Replace(lnTmpl, "store_dir:", fmt.Sprintf(`domain: "%s", store_dir:`, "SA"), 1)
	tmpl = genLeafTmpl(tmpl)

	ln := createJetStreamCluster(t, tmpl, "SA", "SA-", 3, 22280, false)
	ln.waitOnClusterReady()
	defer ln.shutdown()

	for _, s := range ln.servers {
		checkLeafNodeConnectedCount(t, s, 1)
	}

	// Now connect DQ subscribers to each cluster but to the global account.

	// Create 5 clients for each cluster / account
	var c1c, c2c []*nats.Conn
	for i := 0; i < 5; i++ {
		nc1, _ := jsClientConnect(t, c1.randomServer(), nats.UserInfo("efg", "p"))
		defer nc1.Close()
		c1c = append(c1c, nc1)
		nc2, _ := jsClientConnect(t, c2.randomServer(), nats.UserInfo("efg", "p"))
		defer nc2.Close()
		c2c = append(c2c, nc2)
	}

	pending := func(subs []*nats.Subscription) (total int) {
		t.Helper()
		for _, sub := range subs {
			n, _, err := sub.Pending()
			require_NoError(t, err)
			total += n
		}
		return total
	}

	// Make sure no subs to start test
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, false)
		require_True(t, cSnap != nil && len(cSnap) != 0)
		for _, snap := range cSnap {
			require_True(t, snap != nil && !snapSubsExist(snap))
		}
	}
	cSnap := doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, false)
	require_True(t, cSnap != nil && len(cSnap) != 0)
	for _, snap := range cSnap {
		require_True(t, snap != nil && !snapSubsExist(snap))
	}

	// Create Spoke subscribers.
	var rsubs []*nats.Subscription

	// Spread SA subscribers
	for _, srv := range ln.servers {
		nc, _ := jsClientConnect(t, srv)
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA")
		require_NoError(t, err)
		nc.Flush()
		rsubs = append(rsubs, sub)
	}

	// Create a second unique DQ with 10 additional subscribers.
	var rsubs2 = []*nats.Subscription{}

	// Spread SA2 subscribers
	for _, srv := range ln.servers {
		nc, _ := jsClientConnect(t, srv)
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA2")
		require_NoError(t, err)
		nc.Flush()
		rsubs2 = append(rsubs2, sub)
	}

	// sub propogation
	time.Sleep(1 * time.Second)

	// Now connect and send responses from EFG in cloud.
	rando := sc.randomServer()
	// println("RESPONSE publisher rando is", rando.Name())
	nc, _ := jsClientConnect(t, rando, nats.UserInfo("efg", "p"))
	defer nc.Close()

	for i := 0; i < 100; i++ {
		require_NoError(t, nc.Publish("RESPONSE", []byte("OK")))
	}
	nc.Flush()

	checkAllRespReceived := func() error {
		p := pending(rsubs)
		if p == 100 {
			t.Logf("All responses received by SA DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA DQ: %d vs %d", p, 100)
	}

	checkAllRespReceived2 := func() error {
		p := pending(rsubs2)
		if p == 100 {
			t.Logf("All responses received by SA2 DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA2 DQ: %d vs %d", p, 100)
	}

	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived2)
	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived)

	time.Sleep(2 * time.Second)
	// println("State of KSC+STL clusters")
	for _, c := range sc.clusters {
		_ = doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
	}

	// println("State of SA cluster")
	_ = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, true)

	// Now remove all the subscriptions and re-check sub propogration state
	for _, sub := range rsubs {
		sub.Unsubscribe()
	}
	for _, sub := range rsubs2 {
		sub.Unsubscribe()
	}

	time.Sleep(4 * time.Second)
	// println("FINAL State of KSC+STL clusters")
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
		for _, snap := range cSnap {
			require_True(t, !snapSubsExist(snap))
		}
	}

	// println("FINAL State of SA cluster")
	cSnap = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, true)
	for _, snap := range cSnap {
		require_True(t, !snapSubsExist(snap))
	}
}

// This test always fails as we pin leaf subscribers to a spoke node
func TestLeafNodeMCConfigDownlinkOnlyOneLeafAcctNeverSpread(t *testing.T) {
	var tmpl = `
	listen: 127.0.0.1:-1

	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf { listen: 127.0.0.1:-1 }

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {
		EFG {
			users = [ { user: "efg", pass: "p" } ]
			jetstream: enabled
			imports [
				{ stream: { account: STL, subject: "REQUEST"} }
				{ stream: { account: KSC, subject: "REQUEST"} }
			]
			exports [ { stream: "RESPONSE" } ]
		}
		STL {
			users = [ { user: "stl", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		KSC {
			users = [ { user: "ksc", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}`

	sc := createJetStreamSuperClusterWithTemplate(t, tmpl, 3, 2)
	defer sc.shutdown()

	// Now create a leafnode cluster that has 2 LNs, one to each cluster but on separate accounts, ONE and TWO.
	var lnTmpl = `
		listen: 127.0.0.1:-1
		server_name: %s
		jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

		{{leaf}}

		cluster {
			name: %s
			listen: 127.0.0.1:%d
			routes = [%s]
		}

		accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }}
		`

	var leafFrag = `
		leaf {
			listen: 127.0.0.1:-1
			remotes [
				{ urls: [ %s ] }
			]
		}`

	// We want to have two leaf node connections that join to the same local account on the leafnode servers,
	// but connect to different accounts in different clusters.
	c1 := sc.clusters[0] // Will connect to account KSC
	c2 := sc.clusters[1] // Will connect to account STL

	genLeafTmpl := func(tmpl string) string {
		t.Helper()

		var ln1 []string
		for _, s := range c1.servers {
			if s.ClusterName() != c1.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln1 = append(ln1, fmt.Sprintf("nats://ksc:p@%s:%d", ln.Host, ln.Port))
		}

		// Only have SA cluster nodes leaf connect to KSC cluster as ksc user.
		return strings.Replace(tmpl, "{{leaf}}", fmt.Sprintf(leafFrag, strings.Join(ln1, ", ")), 1)
	}

	tmpl = strings.Replace(lnTmpl, "store_dir:", fmt.Sprintf(`domain: "%s", store_dir:`, "SA"), 1)
	tmpl = genLeafTmpl(tmpl)

	ln := createJetStreamCluster(t, tmpl, "SA", "SA-", 3, 22280, false)
	ln.waitOnClusterReady()
	defer ln.shutdown()

	for _, s := range ln.servers {
		checkLeafNodeConnectedCount(t, s, 1)
	}

	// Now connect DQ subscribers to each cluster but to the global account.

	// Create 5 clients for each cluster / account
	var c1c, c2c []*nats.Conn
	for i := 0; i < 5; i++ {
		nc1, _ := jsClientConnect(t, c1.randomServer(), nats.UserInfo("efg", "p"))
		defer nc1.Close()
		c1c = append(c1c, nc1)
		nc2, _ := jsClientConnect(t, c2.randomServer(), nats.UserInfo("efg", "p"))
		defer nc2.Close()
		c2c = append(c2c, nc2)
	}

	pending := func(subs []*nats.Subscription) (total int) {
		t.Helper()
		for _, sub := range subs {
			n, _, err := sub.Pending()
			require_NoError(t, err)
			total += n
		}
		return total
	}

	// Make sure no subs to start test
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, false)
		require_True(t, cSnap != nil && len(cSnap) != 0)
		for _, snap := range cSnap {
			require_True(t, snap != nil && !snapSubsExist(snap))
		}
	}
	cSnap := doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, false)
	require_True(t, cSnap != nil && len(cSnap) != 0)
	for _, snap := range cSnap {
		require_True(t, snap != nil && !snapSubsExist(snap))
	}

	// Create Spoke subscribers.
	var rsubs []*nats.Subscription

	srv := ln.randomServer()
	// Do not spread SA subscribers, all on same node (srv)
	for i := 0; i < 3; i++ {
		nc, _ := jsClientConnect(t, srv)
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA")
		require_NoError(t, err)
		nc.Flush()
		rsubs = append(rsubs, sub)
	}

	// Create a second unique DQ with 10 additional subscribers.
	var rsubs2 = []*nats.Subscription{}

	// we will spread SA2 so it doesn't contribute to fail
	for _, srv := range ln.servers {
		nc, _ := jsClientConnect(t, srv)
		defer nc.Close()
		sub, err := nc.QueueSubscribeSync("RESPONSE", "SA2")
		require_NoError(t, err)
		nc.Flush()
		rsubs2 = append(rsubs2, sub)
	}

	// sub propogation
	time.Sleep(1 * time.Second)

	// Now connect and send responses from EFG in cloud.
	rando := sc.randomServer()
	// println("RESPONSE publisher rando is", rando.Name())
	nc, _ := jsClientConnect(t, rando, nats.UserInfo("efg", "p"))
	defer nc.Close()

	for i := 0; i < 100; i++ {
		require_NoError(t, nc.Publish("RESPONSE", []byte("OK")))
	}
	nc.Flush()

	checkAllRespReceived := func() error {
		p := pending(rsubs)
		if p == 100 {
			t.Logf("All responses received by SA DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA DQ: %d vs %d", p, 100)
	}

	checkAllRespReceived2 := func() error {
		p := pending(rsubs2)
		if p == 100 {
			t.Logf("All responses received by SA2 DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA2 DQ: %d vs %d", p, 100)
	}

	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived2)
	checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived)

	time.Sleep(2 * time.Second)
	// println("State of KSC+STL clusters")
	for _, c := range sc.clusters {
		_ = doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
	}

	// println("State of SA cluster")
	_ = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, true)

	// Now remove all the subscriptions and re-check sub propogration state
	for _, sub := range rsubs {
		sub.Unsubscribe()
	}
	for _, sub := range rsubs2 {
		sub.Unsubscribe()
	}

	time.Sleep(4 * time.Second)
	// println("FINAL State of KSC+STL clusters")
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
		for _, snap := range cSnap {
			require_True(t, !snapSubsExist(snap))
		}
	}

	// println("FINAL State of SA cluster")
	cSnap = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, false)
	for _, snap := range cSnap {
		require_True(t, !snapSubsExist(snap))
	}
}

// This test always fails as we pin leaf subscribers to a spoke node
func TestLeafNodeMCConfigDownlinkOnlyOneLeafAcctNeverSpreadRepeat(t *testing.T) {
	var tmpl = `
	listen: 127.0.0.1:-1

	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf { listen: 127.0.0.1:-1 }

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {
		EFG {
			users = [ { user: "efg", pass: "p" } ]
			jetstream: enabled
			imports [
				{ stream: { account: STL, subject: "REQUEST"} }
				{ stream: { account: KSC, subject: "REQUEST"} }
			]
			exports [ { stream: "RESPONSE" } ]
		}
		STL {
			users = [ { user: "stl", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		KSC {
			users = [ { user: "ksc", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}`

	sc := createJetStreamSuperClusterWithTemplate(t, tmpl, 5, 2)
	defer sc.shutdown()

	// Now create a leafnode cluster that has 2 LNs, one to each cluster but on separate accounts, ONE and TWO.
	var lnTmpl = `
		listen: 127.0.0.1:-1
		server_name: %s
		jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

		{{leaf}}

		cluster {
			name: %s
			listen: 127.0.0.1:%d
			routes = [%s]
		}

		accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }}
		`

	var leafFrag = `
		leaf {
			listen: 127.0.0.1:-1
			remotes [
				{ urls: [ %s ] }
			]
		}`

	// We want to have two leaf node connections that join to the same local account on the leafnode servers,
	// but connect to different accounts in different clusters.
	c1 := sc.clusters[0] // Will connect to account KSC
	c2 := sc.clusters[1] // Will connect to account STL

	genLeafTmpl := func(tmpl string) string {
		t.Helper()

		var ln1 []string
		for _, s := range c1.servers {
			if s.ClusterName() != c1.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln1 = append(ln1, fmt.Sprintf("nats://ksc:p@%s:%d", ln.Host, ln.Port))
		}

		// Only have SA cluster nodes leaf connect to KSC cluster as ksc user.
		return strings.Replace(tmpl, "{{leaf}}", fmt.Sprintf(leafFrag, strings.Join(ln1, ", ")), 1)
	}

	tmpl = strings.Replace(lnTmpl, "store_dir:", fmt.Sprintf(`domain: "%s", store_dir:`, "SA"), 1)
	tmpl = genLeafTmpl(tmpl)

	ln := createJetStreamCluster(t, tmpl, "SA", "SA-", 3, 22280, false)
	ln.waitOnClusterReady()
	defer ln.shutdown()

	for _, s := range ln.servers {
		checkLeafNodeConnectedCount(t, s, 1)
	}

	// Now connect DQ subscribers to each cluster but to the global account.

	// Create 5 clients for each cluster / account
	var c1c, c2c []*nats.Conn
	for i := 0; i < 5; i++ {
		nc1, _ := jsClientConnect(t, c1.randomServer(), nats.UserInfo("efg", "p"))
		defer nc1.Close()
		c1c = append(c1c, nc1)
		nc2, _ := jsClientConnect(t, c2.randomServer(), nats.UserInfo("efg", "p"))
		defer nc2.Close()
		c2c = append(c2c, nc2)
	}

	pending := func(subs []*nats.Subscription) (total int) {
		t.Helper()
		for _, sub := range subs {
			n, _, err := sub.Pending()
			require_NoError(t, err)
			total += n
		}
		return total
	}

	// Make sure no subs to start test
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, false)
		require_True(t, cSnap != nil && len(cSnap) != 0)
		for _, snap := range cSnap {
			require_True(t, snap != nil && !snapSubsExist(snap))
		}
	}
	cSnap := doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, false)
	require_True(t, cSnap != nil && len(cSnap) != 0)
	for _, snap := range cSnap {
		require_True(t, snap != nil && !snapSubsExist(snap))
	}

	// Create Spoke subscribers.
	var rsubs []*nats.Subscription
	var rncs []*nats.Conn
	// Create a second unique DQ to test for any cross-talk (not seeing so far).
	var rsubs2 = []*nats.Subscription{}
	var rncs2 = []*nats.Conn{}

	var spokeSubNow = func(sindex int) {
		// NeverSpread
		rsubs = nil
		srv := ln.servers[sindex]
		for i := 0; i < 5; i++ {
			nc, _ := jsClientConnect(t, srv)
			// defer nc.Close()
			rncs = append(rncs, nc)
			sub, err := nc.QueueSubscribeSync("RESPONSE", "SA")
			require_NoError(t, err)
			nc.Flush()
			rsubs = append(rsubs, sub)
		}

		// we will spread SA2 so it doesn't contribute to fail
		rsubs2 = nil
		for _, srv := range ln.servers {
			nc, _ := jsClientConnect(t, srv)
			// defer nc.Close()
			rncs2 = append(rncs2, nc)
			sub, err := nc.QueueSubscribeSync("RESPONSE", "SA2")
			require_NoError(t, err)
			nc.Flush()
			rsubs2 = append(rsubs2, sub)
		}

		// sub propogation
		time.Sleep(1 * time.Second)
	}

	var spokeUnsubNow = func() {
		// Now remove all the subscriptions and re-check sub propogration state
		for _, sub := range rsubs {
			sub.Unsubscribe()
		}
		for _, sub := range rsubs2 {
			sub.Unsubscribe()
		}
	}

	var _ = func() {
		// Now remove all the subscriptions and re-check sub propogration state
		for _, nc := range rncs {
			nc.Close()
		}
		for _, nc := range rncs2 {
			nc.Close()
		}
	}

	var doHubPubsNow = func() {
		// Now connect and send responses from EFG in cloud.
		rando := sc.randomServer()
		// println("RESPONSE publisher rando is", rando.Name())
		nc, _ := jsClientConnect(t, rando, nats.UserInfo("efg", "p"))
		defer nc.Close()

		for i := 0; i < 100; i++ {
			require_NoError(t, nc.Publish("RESPONSE", []byte("OK")))
		}
		nc.Flush()
	}

	checkAllRespReceived := func() error {
		p := pending(rsubs)
		if p == 100 {
			t.Logf("All responses received by SA DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA DQ: %d vs %d", p, 100)
	}

	checkAllRespReceived2 := func() error {
		p := pending(rsubs2)
		if p == 100 {
			t.Logf("All responses received by SA2 DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA2 DQ: %d vs %d", p, 100)
	}

	// Let's subcribe-pub-check-unsub more than once to see if it fails after first time success...
	// Do up to three times to select different spoke server each round
	for test := 0; test < 3; test++ {
		println("Test", test, "Spoke server:", ln.servers[test].Name())
		spokeSubNow(test)
		doHubPubsNow()
		checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived2)
		checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived)

		time.Sleep(2 * time.Second)
		//println("State of KSC+STL clusters")
		//for _, c := range sc.clusters {
		//	_ = doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
		//}
		//
		//println("State of SA cluster")
		//_ = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, true)

		// See if any difference in UNSUB if by closed connections at spoke
		// spokeClientDisconnNow()
		spokeUnsubNow()
	}
	// Temporarily remove the complete unsub check because we know it fails. This test will see if we can make publish
	// fail with multiple iterations of incomplete unsub at HUB, such as phantom EFG sub directly traffic to leaf
	// connection with no actual client sub...
	time.Sleep(4 * time.Second)
	// println("FINAL State of KSC+STL clusters")
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
		for _, snap := range cSnap {
			require_True(t, !snapSubsExist(snap))
		}
	}

	// println("FINAL State of SA cluster")
	cSnap = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, false)
	for _, snap := range cSnap {
		require_True(t, !snapSubsExist(snap))
	}

	// Clean up our test for closes that weren't deferred to test return
	// spokeClientDisconnNow()
}

// STL and KSC leaf remotes; This test always fails as we pin leaf subscribers to a spoke node
func TestLeafNodeMCConfigDownlinkOnlyTwoLeafAcctNeverSpreadRepeat(t *testing.T) {
	var tmpl = `
	listen: 127.0.0.1:-1

	server_name: %s
	jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

	leaf { listen: 127.0.0.1:-1 }

	cluster {
		name: %s
		listen: 127.0.0.1:%d
		routes = [%s]
	}

	accounts {
		EFG {
			users = [ { user: "efg", pass: "p" } ]
			jetstream: enabled
			imports [
				{ stream: { account: STL, subject: "REQUEST"} }
				{ stream: { account: KSC, subject: "REQUEST"} }
			]
			exports [ { stream: "RESPONSE" } ]
		}
		STL {
			users = [ { user: "stl", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		KSC {
			users = [ { user: "ksc", pass: "p" } ]
			exports [ { stream: "REQUEST" } ]
			imports [ { stream: { account: EFG, subject: "RESPONSE"} } ]
		}
		$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
	}`

	sc := createJetStreamSuperClusterWithTemplate(t, tmpl, 3, 2)
	defer sc.shutdown()

	// Now create a leafnode cluster that has 2 LNs, one to each cluster but on separate accounts, ONE and TWO.
	var lnTmpl = `
		listen: 127.0.0.1:-1
		server_name: %s
		jetstream: {max_mem_store: 256MB, max_file_store: 2GB, store_dir: '%s'}

		{{leaf}}

		cluster {
			name: %s
			listen: 127.0.0.1:%d
			routes = [%s]
		}

		accounts { $SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }}
		`

	var leafFrag = `
		leaf {
			listen: 127.0.0.1:-1
			remotes [
				{ urls: [ %s ] }
				{ urls: [ %s ] }
			]
		}`

	// We want to have two leaf node connections that join to the same local account on the leafnode servers,
	// but connect to different accounts in different clusters.
	c1 := sc.clusters[0] // Will connect to account KSC
	c2 := sc.clusters[1] // Will connect to account STL

	genLeafTmpl := func(tmpl string) string {
		t.Helper()

		var ln1, ln2 []string
		for _, s := range c1.servers {
			if s.ClusterName() != c1.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln1 = append(ln1, fmt.Sprintf("nats://ksc:p@%s:%d", ln.Host, ln.Port))
		}

		for _, s := range c2.servers {
			if s.ClusterName() != c2.name {
				continue
			}
			ln := s.getOpts().LeafNode
			ln2 = append(ln2, fmt.Sprintf("nats://stl:p@%s:%d", ln.Host, ln.Port))
		}

		// Only have SA cluster nodes leaf connect to KSC cluster as ksc user.
		return strings.Replace(tmpl, "{{leaf}}", fmt.Sprintf(leafFrag, strings.Join(ln1, ", "), strings.Join(ln2, ", ")), 1)
	}

	tmpl = strings.Replace(lnTmpl, "store_dir:", fmt.Sprintf(`domain: "%s", store_dir:`, "SA"), 1)
	tmpl = genLeafTmpl(tmpl)

	ln := createJetStreamCluster(t, tmpl, "SA", "SA-", 5, 22280, false)
	ln.waitOnClusterReady()
	defer ln.shutdown()

	for _, s := range ln.servers {
		checkLeafNodeConnectedCount(t, s, 2)
	}

	// Now connect DQ subscribers to each cluster but to the global account.

	// Create 5 clients for each cluster / account
	var c1c, c2c []*nats.Conn
	for i := 0; i < 5; i++ {
		nc1, _ := jsClientConnect(t, c1.randomServer(), nats.UserInfo("efg", "p"))
		defer nc1.Close()
		c1c = append(c1c, nc1)
		nc2, _ := jsClientConnect(t, c2.randomServer(), nats.UserInfo("efg", "p"))
		defer nc2.Close()
		c2c = append(c2c, nc2)
	}

	pending := func(subs []*nats.Subscription) (total int) {
		t.Helper()
		for _, sub := range subs {
			n, _, err := sub.Pending()
			require_NoError(t, err)
			total += n
		}
		return total
	}

	// Make sure no subs to start test
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, false)
		require_True(t, cSnap != nil && len(cSnap) != 0)
		for _, snap := range cSnap {
			require_True(t, snap != nil && !snapSubsExist(snap))
		}
	}
	cSnap := doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, false)
	require_True(t, cSnap != nil && len(cSnap) != 0)
	for _, snap := range cSnap {
		require_True(t, snap != nil && !snapSubsExist(snap))
	}

	// Create Spoke subscribers.
	var rsubs []*nats.Subscription
	var rncs []*nats.Conn
	// Create a second unique DQ to test for any cross-talk (not seeing so far).
	var rsubs2 = []*nats.Subscription{}
	var rncs2 = []*nats.Conn{}

	var spokeSubNow = func(sindex int) {
		// NeverSpread
		rsubs = nil
		srv := ln.servers[sindex]
		for i := 0; i < 3; i++ {
			nc, _ := jsClientConnect(t, srv)
			// defer nc.Close()
			rncs = append(rncs, nc)
			sub, err := nc.QueueSubscribeSync("RESPONSE", "SA")
			require_NoError(t, err)
			nc.Flush()
			rsubs = append(rsubs, sub)
		}

		// we will spread SA2 so it doesn't contribute to fail
		rsubs2 = nil
		for _, srv := range ln.servers {
			nc, _ := jsClientConnect(t, srv)
			// defer nc.Close()
			rncs2 = append(rncs2, nc)
			sub, err := nc.QueueSubscribeSync("RESPONSE", "SA2")
			require_NoError(t, err)
			nc.Flush()
			rsubs2 = append(rsubs2, sub)
		}

		// sub propogation
		time.Sleep(1 * time.Second)
	}

	var spokeUnsubNow = func() {
		// Now remove all the subscriptions and re-check sub propogration state
		for _, sub := range rsubs {
			sub.Unsubscribe()
		}
		for _, sub := range rsubs2 {
			sub.Unsubscribe()
		}
	}

	var _ = func() {
		// Now remove all the subscriptions and re-check sub propogration state
		for _, nc := range rncs {
			nc.Close()
		}
		for _, nc := range rncs2 {
			nc.Close()
		}
	}

	var doHubPubsNow = func() {
		// Now connect and send responses from EFG in cloud.
		rando := sc.randomServer()
		// println("RESPONSE publisher rando is", rando.Name())
		nc, _ := jsClientConnect(t, rando, nats.UserInfo("efg", "p"))
		defer nc.Close()

		for i := 0; i < 100; i++ {
			require_NoError(t, nc.Publish("RESPONSE", []byte("OK")))
		}
		nc.Flush()
	}

	checkAllRespReceived := func() error {
		p := pending(rsubs)
		if p == 100 {
			t.Logf("All responses received by SA DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA DQ: %d vs %d", p, 100)
	}

	checkAllRespReceived2 := func() error {
		p := pending(rsubs2)
		if p == 100 {
			t.Logf("All responses received by SA2 DQ [%d]", p)
			return nil
		}
		return fmt.Errorf("Not all responses received by SA2 DQ: %d vs %d", p, 100)
	}

	// Let's subcribe-pub-check-unsub more than once to see if it fails after first time success...
	// Do up to three times to select different spoke server each round
	for test := 0; test < 5; test++ {
		println("Test", test, "Spoke server:", ln.servers[test].Name())
		spokeSubNow(test)
		doHubPubsNow()
		checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived2)
		checkFor(t, time.Second, 200*time.Millisecond, checkAllRespReceived)

		time.Sleep(2 * time.Second)
		//println("State of KSC+STL clusters")
		//for _, c := range sc.clusters {
		//	_ = doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
		//}
		//
		//println("State of SA cluster")
		//_ = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, true)

		// See if any difference in UNSUB if by closed connections at spoke
		// spokeClientDisconnNow()
		spokeUnsubNow()
	}
	// Temporarily remove the complete unsub check because we know it fails. This test will see if we can make publish
	// fail with multiple iterations of incomplete unsub at HUB, such as phantom EFG sub directly traffic to leaf
	// connection with no actual client sub...
	time.Sleep(4 * time.Second)
	for _, c := range sc.clusters {
		_ = doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, true)
	}
	for _, c := range sc.clusters {
		cSnap := doSnapSubzForSubjectOnCluster(c, "RESPONSE", []string{"KSC", "STL", "EFG"}, false)
		for _, snap := range cSnap {
			require_True(t, !snapSubsExist(snap))
		}
	}

	// println("FINAL State of SA cluster")
	cSnap = doSnapSubzForSubjectOnCluster(ln, "RESPONSE", []string{"$G"}, false)
	for _, snap := range cSnap {
		require_True(t, !snapSubsExist(snap))
	}

	// Clean up our test for closes that weren't deferred to test return
	// spokeClientDisconnNow()
}
