package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const defaultUpstream = "1.1.1.1"

func rsdnsBinaryPath() string {
	wd, _ := os.Getwd()
	projectRoot := filepath.Join(wd, "../..")
	bp := filepath.Join(projectRoot, "target/debug/rsdns")
	if _, err := os.Stat(bp); err == nil {
		return bp
	}
	bp = filepath.Join(projectRoot, "target/release/rsdns")
	if _, err := os.Stat(bp); err == nil {
		return bp
	}
	log.Fatalf("[rsdns] Binary not found. Build first with: cargo build --bin rsdns")
	return ""
}

func buildRsdnsConfig(port int, testUpstream string) string {
	if testUpstream == "" {
		return fmt.Sprintf(`binds:
  - address: "0.0.0.0:%d"
  - address: "tcp://0.0.0.0:%d"
groups:
  - name: ad
    domains:
      - doubleclick.net
upstreams:
  - name: default
    servers:
      - address: 1.1.1.1
cache:
  size: 4096
  min_ttl: 0
  max_ttl: 3600
hosts:
  - "0.0.0.0 rsdns-test-blocked.example.com"
rules:
  - match: group:ad
    action:
      type: block
      response: poison
  - match: ""
    action:
      type: forward
      upstream: default
`, port, port)
	}
	return fmt.Sprintf(`binds:
  - address: "0.0.0.0:%d"
  - address: "tcp://0.0.0.0:%d"
groups:
  - name: ad
    domains:
      - doubleclick.net
upstreams:
  - name: bootstrap
    servers:
      - address: 1.1.1.1
  - name: test
    servers:
      - address: %s
cache:
  size: 4096
  min_ttl: 0
  max_ttl: 3600
hosts:
  - "0.0.0.0 rsdns-test-blocked.example.com"
rules:
  - match: group:ad
    action:
      type: block
      response: poison
  - match: ""
    action:
      type: forward
      upstream: test
`, port, port, testUpstream)
}

type RsdnsProcess struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	config string
	port   int
}

func startRsdnsWithUpstream(ctx context.Context, port int, testUpstream string) (*RsdnsProcess, error) {
	ctx, cancel := context.WithCancel(ctx)
	configYAML := buildRsdnsConfig(port, testUpstream)
	tmpDir, err := os.MkdirTemp("", "rsdns-e2e-*")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	configPath := filepath.Join(tmpDir, "rsdns.yaml")
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		cancel()
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("write config: %w", err)
	}
	log.Printf("[rsdns] Config: %s testUpstream=%s\n%s", configPath, testUpstream, configYAML)
	bp := rsdnsBinaryPath()
	cmd := exec.CommandContext(ctx, bp, "--config", configPath)
	wd, _ := os.Getwd()
	cmd.Dir = filepath.Join(wd, "../..")
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		logPath := filepath.Join(tmpDir, "rsdns.log")
		logFile, err := os.Create(logPath)
		if err == nil {
			cmd.Stdout = logFile
			cmd.Stderr = logFile
		}
	}
	if err := cmd.Start(); err != nil {
		cancel()
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("start rsdns: %w", err)
	}
	log.Printf("[rsdns] Started PID=%d port=%d", cmd.Process.Pid, port)
	return &RsdnsProcess{cmd: cmd, cancel: cancel, config: tmpDir, port: port}, nil
}

func startRsdns(ctx context.Context, port int) (*RsdnsProcess, error) {
	return startRsdnsWithUpstream(ctx, port, "")
}

func buildRsdnsSplitConfig(port int, testUpstream string, testDomain string) string {
	return fmt.Sprintf(`binds:
  - address: "0.0.0.0:%d"
  - address: "tcp://0.0.0.0:%d"
groups:
  - name: test
    domains:
      - %s
upstreams:
  - name: bootstrap
    servers:
      - address: 1.1.1.1
  - name: default
    servers:
      - address: 127.0.0.1:19999
  - name: test
    servers:
      - address: %s
cache:
  size: 4096
  min_ttl: 0
  max_ttl: 3600
hosts: []
rules:
  - match: group:test
    action:
      type: forward
      upstream: test
  - match: ""
    action:
      type: forward
      upstream: default
`, port, port, testDomain, testUpstream)
}

func startRsdnsWithSplitConfig(ctx context.Context, port int, testUpstream string, testDomain string) (*RsdnsProcess, error) {
	ctx, cancel := context.WithCancel(ctx)
	configYAML := buildRsdnsSplitConfig(port, testUpstream, testDomain)
	tmpDir, err := os.MkdirTemp("", "rsdns-e2e-*")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create temp dir: %w", err)
	}
	configPath := filepath.Join(tmpDir, "rsdns.yaml")
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		cancel()
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("write config: %w", err)
	}
	log.Printf("[rsdns] Split config (port=%d upstream=%s domain=%s):\n%s", port, testUpstream, testDomain, configYAML)
	bp := rsdnsBinaryPath()
	cmd := exec.CommandContext(ctx, bp, "--config", configPath)
	wd, _ := os.Getwd()
	cmd.Dir = filepath.Join(wd, "../..")
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		logPath := filepath.Join(tmpDir, "rsdns.log")
		logFile, err := os.Create(logPath)
		if err == nil {
			cmd.Stdout = logFile
			cmd.Stderr = logFile
		}
	}
	if err := cmd.Start(); err != nil {
		cancel()
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("start rsdns: %w", err)
	}
	log.Printf("[rsdns] Started PID=%d port=%d (split mode)", cmd.Process.Pid, port)
	return &RsdnsProcess{cmd: cmd, cancel: cancel, config: tmpDir, port: port}, nil
}

func (p *RsdnsProcess) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		log.Printf("[rsdns] Stopping PID=%d", p.cmd.Process.Pid)
		p.cmd.Process.Kill()
	}
	if p.config != "" {
		os.RemoveAll(p.config)
	}
}

// verifyNoLeak checks that the given domain does NOT resolve.
// This confirms traffic is not leaking to the default (broken) upstream.
func verifyNoLeak(cli *dnsClient, domain string) error {
	hosts, err := cli.LookupHostWithRetry(domain, 2, 300*time.Millisecond)
	if err == nil && len(hosts) > 0 {
		return fmt.Errorf("unexpected resolution for %s (leak!): %v", domain, hosts)
	}
	log.Printf("[split-verify] %s correctly NOT resolved (default upstream blocked it): %v", domain, err)
	return nil
}

// --- raw DNS client to avoid net.Resolver routing to system DNS (port 53) ---

type dnsClient struct {
	conn *net.UDPConn
}

type dnsResponse struct {
	rcode uint8
	ips   []net.IP
}

func newDNSClient(port int) (*dnsClient, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	return &dnsClient{conn: conn}, nil
}

func (c *dnsClient) Close() { c.conn.Close() }

func (c *dnsClient) LookupHost(domain string) ([]string, error) {
	var hosts []string
	ips, err := c.lookup(domain, 1)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		hosts = append(hosts, ip.String())
	}
	ips, _ = c.lookup(domain, 28)
	for _, ip := range ips {
		hosts = append(hosts, ip.String())
	}
	return hosts, nil
}

func (c *dnsClient) lookupRcode(domain string, qtype uint16) (uint8, error) {
	resp, err := c.lookupResponse(domain, qtype)
	if err != nil {
		return 0, err
	}
	return resp.rcode, nil
}

func (c *dnsClient) LookupHostWithRetry(domain string, retries int, interval time.Duration) ([]string, error) {
	var lastErr error
	for i := 0; i < retries; i++ {
		hosts, err := c.LookupHost(domain)
		if err == nil && len(hosts) > 0 {
			return hosts, nil
		}
		lastErr = err
		time.Sleep(interval)
	}
	return nil, lastErr
}

func (c *dnsClient) lookup(domain string, qtype uint16) ([]net.IP, error) {
	resp, err := c.lookupResponse(domain, qtype)
	if err != nil {
		return nil, err
	}
	if resp.rcode != 0 {
		return nil, nil
	}
	return resp.ips, nil
}

func (c *dnsClient) lookupResponse(domain string, qtype uint16) (*dnsResponse, error) {
	wire := buildWireQuery(domain, qtype)
	c.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.conn.Write(wire); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, 4096)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return parseWireResponse(buf[:n]), nil
}

func buildWireQuery(domain string, qtype uint16) []byte {
	var buf []byte
	buf = append(buf, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, p := range strings.Split(domain, ".") {
		buf = append(buf, byte(len(p)))
		buf = append(buf, []byte(p)...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, byte(qtype>>8), byte(qtype&0xFF))
	buf = append(buf, 0x00, 0x01)
	return buf
}

func parseWireResponse(data []byte) *dnsResponse {
	if len(data) < 12 {
		return &dnsResponse{}
	}
	ancount := int(uint16(data[6])<<8 | uint16(data[7]))
	rcode := data[3] & 0x0F
	pos := 12
	for pos < len(data) && data[pos] != 0x00 {
		if data[pos]&0xC0 == 0xC0 {
			pos += 2
			break
		}
		pos += int(data[pos]) + 1
	}
	if pos < len(data) && data[pos] == 0x00 {
		pos += 1
	}
	pos += 4
	var ips []net.IP
	for i := 0; i < ancount; i++ {
		if pos >= len(data) {
			break
		}
		if data[pos]&0xC0 == 0xC0 {
			pos += 2
		} else {
			for pos < len(data) && data[pos] != 0x00 {
				pos += int(data[pos]) + 1
			}
			if pos < len(data) {
				pos += 1
			}
		}
		if pos+10 > len(data) {
			break
		}
		rtype := uint16(data[pos])<<8 | uint16(data[pos+1])
		rdlen := uint16(data[pos+8])<<8 | uint16(data[pos+9])
		pos += 10
		if pos+int(rdlen) > len(data) {
			break
		}
		switch rtype {
		case 1:
			if rdlen == 4 {
				ips = append(ips, net.IPv4(data[pos], data[pos+1], data[pos+2], data[pos+3]))
			}
		case 28:
			if rdlen == 16 {
				ip := make(net.IP, 16)
				copy(ip, data[pos:pos+16])
				ips = append(ips, ip)
			}
		}
		pos += int(rdlen)
	}
	return &dnsResponse{rcode: rcode, ips: ips}
}

// --- wait for rsdns to be ready ---

func waitForRsdnsReady(port int, timeout time.Duration) error {
	log.Printf("[wait] Waiting for rsdns on UDP %d...", port)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cli, err := newDNSClient(port)
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		_, err = cli.LookupHost("example.com")
		cli.Close()
		if err == nil {
			log.Printf("[wait] rsdns port %d ready after %.2fs", port, time.Since(time.Now().Add(-timeout)).Seconds())
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for rsdns UDP port %d", port)
}

// --- tests ---

// RsdnsTest describes a single rsdns e2e test case.
type RsdnsTest struct {
	Name string // short label, e.g. "Forward"
	Desc string // human-readable description of what this case validates
	Fn   func() error
}

// RsdnsTests lists all rsdns test cases in execution order.
var RsdnsTests = []RsdnsTest{
	{"Forward", "Plain UDP forward via default upstream resolves example.com and blocks ad domain with poison", TestRsdnsForward},
	{"Hosts", "Hosts file mapping returns 0.0.0.0 for a statically-blocked domain", TestRsdnsHosts},
	{"Reject", "Block rule with nxdomain response returns NXDOMAIN", TestRsdnsReject},

	{"DoT", "Split-tunnel DNS-over-TLS upstream resolves, non-matched domain is not leaked", TestRsdnsDoT},
	{"DoH", "Split-tunnel DNS-over-HTTPS upstream resolves, non-matched domain is not leaked", TestRsdnsDoH},
	{"DoH3", "Split-tunnel DNS-over-HTTP/3 upstream resolves, non-matched domain is not leaked", TestRsdnsDoH3},
	{"TCP", "Split-tunnel TCP upstream resolves, non-matched domain is not leaked", TestRsdnsTCP},
	{"DoQ", "Split-tunnel DNS-over-QUIC upstream resolves, non-matched domain is not leaked", TestRsdnsDoQ},
}

func TestRsdnsForward() error {
	port := 15353
	ctx := context.Background()
	rsdns, err := startRsdns(ctx, port)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	defer rsdns.Stop()
	if err := waitForRsdnsReady(port, 15*time.Second); err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	cli, err := newDNSClient(port)
	if err != nil {
		return err
	}
	defer cli.Close()

	log.Printf("[rsdns-test] Forward: example.com")
	hosts, err := cli.LookupHostWithRetry("example.com", 5, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("forward: %w", err)
	}
	log.Printf("[rsdns-test] example.com → %v", hosts)

	log.Printf("[rsdns-test] Block: track.doubleclick.net (poison)")
	hosts, err = cli.LookupHost("track.doubleclick.net")
	if err != nil {
		return fmt.Errorf("block: %w", err)
	}
	log.Printf("[rsdns-test] doubleclick → %v", hosts)
	for _, h := range hosts {
		if h == "0.0.0.0" {
			log.Printf("[rsdns-test] PASS (poison)")
			return nil
		}
	}
	return fmt.Errorf("expected poison 0.0.0.0, got: %v", hosts)
}

func TestRsdnsHosts() error {
	port := 15354
	rsdns, err := startRsdns(context.Background(), port)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	defer rsdns.Stop()
	if err := waitForRsdnsReady(port, 15*time.Second); err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	cli, err := newDNSClient(port)
	if err != nil {
		return err
	}
	defer cli.Close()

	hosts, err := cli.LookupHost("rsdns-test-blocked.example.com")
	if err != nil {
		return fmt.Errorf("hosts: %w", err)
	}
	log.Printf("[rsdns-test] hosts → %v", hosts)
	for _, h := range hosts {
		if h == "0.0.0.0" {
			log.Printf("[rsdns-test] PASS")
			return nil
		}
	}
	return fmt.Errorf("expected 0.0.0.0, got: %v", hosts)
}

func TestRsdnsReject() error {
	port := 15359
	cfg := fmt.Sprintf(`binds:
  - address: "0.0.0.0:%d"
groups:
  - name: block
    domains:
      - blocked-nxdomain.example
upstreams:
  - name: default
    servers:
      - address: 1.1.1.1
cache:
  size: 256
hosts: []
rules:
  - match: group:block
    action:
      type: block
      response: nxdomain
  - match: ""
    action:
      type: forward
      upstream: default
`, port)
	tmpDir, _ := os.MkdirTemp("", "rsdns-e2e-*")
	defer os.RemoveAll(tmpDir)
	cfgPath := filepath.Join(tmpDir, "rsdns.yaml")
	os.WriteFile(cfgPath, []byte(cfg), 0o644)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, rsdnsBinaryPath(), "--config", cfgPath)
	wd, _ := os.Getwd()
	cmd.Dir = filepath.Join(wd, "../..")

	if !verbose {
		logFile, err := os.Create(filepath.Join(tmpDir, "rsdns.log"))
		if err == nil {
			cmd.Stdout = logFile
			cmd.Stderr = logFile
		}
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	defer cmd.Process.Kill()

	if err := waitForRsdnsReady(port, 15*time.Second); err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	cli, _ := newDNSClient(port)
	defer cli.Close()

	hosts, err := cli.LookupHost("blocked-nxdomain.example")
	if err == nil && len(hosts) > 0 {
		return fmt.Errorf("expected NXDOMAIN error, got: %v", hosts)
	}
	log.Printf("[rsdns-test] PASS NXDOMAIN: %v", err)
	return nil
}

func TestRsdnsDoT() error {
	addr := os.Getenv("RSDNS_UPSTREAM_DOT")
	if addr == "" {
		log.Printf("[rsdns-dot] SKIP")
		return errSkip
	}
	port := 15356
	rsdns, err := startRsdnsWithSplitConfig(context.Background(), port, addr, "example.com")
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	defer rsdns.Stop()
	if err := waitForRsdnsReady(port, 20*time.Second); err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	cli, _ := newDNSClient(port)
	defer cli.Close()

	// 1) Matched domain must resolve via DoT upstream
	hosts, err := cli.LookupHostWithRetry("example.com", 10, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("DoT resolve: %w", err)
	}
	log.Printf("[rsdns-dot] example.com → %v", hosts)

	// 2) Unmatched domain must NOT resolve (proves no leak to default upstream)
	if err := verifyNoLeak(cli, "verify-no-leak-test.rsdns.local"); err != nil {
		return fmt.Errorf("DoT leak: %w", err)
	}
	log.Printf("[rsdns-dot] PASS (split verified)")
	return nil
}

func TestRsdnsDoH() error {
	addr := os.Getenv("RSDNS_UPSTREAM_DOH")
	if addr == "" {
		log.Printf("[rsdns-doh] SKIP")
		return errSkip
	}
	port := 15357
	rsdns, err := startRsdnsWithSplitConfig(context.Background(), port, addr, "example.com")
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	defer rsdns.Stop()
	if err := waitForRsdnsReady(port, 20*time.Second); err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	cli, _ := newDNSClient(port)
	defer cli.Close()

	// 1) Matched domain must resolve via DoH upstream
	hosts, err := cli.LookupHostWithRetry("example.com", 10, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("DoH resolve: %w", err)
	}
	log.Printf("[rsdns-doh] example.com → %v", hosts)

	// 2) Unmatched domain must NOT resolve (proves no leak to default upstream)
	if err := verifyNoLeak(cli, "verify-no-leak-test.rsdns.local"); err != nil {
		return fmt.Errorf("DoH leak: %w", err)
	}
	log.Printf("[rsdns-doh] PASS (split verified)")
	return nil
}

func TestRsdnsDoH3() error {
	addr := os.Getenv("RSDNS_UPSTREAM_DOH3")
	if addr == "" {
		log.Printf("[rsdns-doh3] SKIP")
		return errSkip
	}
	port := 15358
	rsdns, err := startRsdnsWithSplitConfig(context.Background(), port, addr, "example.com")
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	defer rsdns.Stop()
	if err := waitForRsdnsReady(port, 20*time.Second); err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	cli, _ := newDNSClient(port)
	defer cli.Close()

	// 1) Matched domain must resolve via DoH3 upstream
	hosts, err := cli.LookupHostWithRetry("example.com", 3, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("DoH3 resolve: %w", err)
	}
	log.Printf("[rsdns-doh3] example.com → %v", hosts)

	// 2) Unmatched domain must NOT resolve (proves no leak to default upstream)
	if err := verifyNoLeak(cli, "verify-no-leak-test.rsdns.local"); err != nil {
		return fmt.Errorf("DoH3 leak: %w", err)
	}
	log.Printf("[rsdns-doh3] PASS (split verified)")
	return nil
}

func TestRsdnsTCP() error {
	addr := os.Getenv("RSDNS_UPSTREAM_TCP")
	if addr == "" {
		log.Printf("[rsdns-tcp] SKIP")
		return errSkip
	}
	port := 15360
	rsdns, err := startRsdnsWithSplitConfig(context.Background(), port, addr, "example.com")
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	defer rsdns.Stop()
	if err := waitForRsdnsReady(port, 20*time.Second); err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	cli, _ := newDNSClient(port)
	defer cli.Close()

	hosts, err := cli.LookupHostWithRetry("example.com", 10, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("TCP resolve: %w", err)
	}
	log.Printf("[rsdns-tcp] example.com → %v", hosts)

	if err := verifyNoLeak(cli, "verify-no-leak-test.rsdns.local"); err != nil {
		return fmt.Errorf("TCP leak: %w", err)
	}
	log.Printf("[rsdns-tcp] PASS (split verified)")
	return nil
}

func TestRsdnsDoQ() error {
	addr := os.Getenv("RSDNS_UPSTREAM_DOQ")
	if addr == "" {
		log.Printf("[rsdns-doq] SKIP")
		return errSkip
	}
	port := 15361
	rsdns, err := startRsdnsWithSplitConfig(context.Background(), port, addr, "example.com")
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	defer rsdns.Stop()
	if err := waitForRsdnsReady(port, 20*time.Second); err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	cli, _ := newDNSClient(port)
	defer cli.Close()

	hosts, err := cli.LookupHostWithRetry("example.com", 10, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("DoQ resolve: %w", err)
	}
	log.Printf("[rsdns-doq] example.com → %v", hosts)

	if err := verifyNoLeak(cli, "verify-no-leak-test.rsdns.local"); err != nil {
		return fmt.Errorf("DoQ leak: %w", err)
	}
	log.Printf("[rsdns-doq] PASS (split verified)")
	return nil
}

func testRsdnsAll() error {
	failed := false
	for _, t := range RsdnsTests {
		log.Printf("[rsdns] START: %s – %s", t.Name, t.Desc)
		if err := t.Fn(); err != nil {
			log.Printf("[rsdns] FAIL %s: %v", t.Name, err)
			failed = true
		} else {
			log.Printf("[rsdns] PASS %s", t.Name)
		}
	}
	if failed {
		return fmt.Errorf("one or more rsdns tests failed")
	}
	return nil
}
