package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

var (
	projectRoot string
	binaryPath  string
	verbose     bool
	configPath  string
	config      E2EConfig
)

// E2EConfig controls the default resolver, selected cases, and protocol-specific upstreams.
type E2EConfig struct {
	DefaultUpstream string            `json:"default_upstream"`
	Tests           []string          `json:"tests"`
	Upstreams       map[string]string `json:"upstreams"`
}

func (c E2EConfig) includes(name string) bool {
	for _, selected := range c.Tests {
		if selected == name {
			return true
		}
	}
	return false
}

func (c E2EConfig) upstream(name string) string {
	return c.Upstreams[name]
}

func loadConfig(path string) (E2EConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return E2EConfig{}, err
	}
	var cfg E2EConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return E2EConfig{}, err
	}
	if cfg.DefaultUpstream == "" {
		return E2EConfig{}, fmt.Errorf("default_upstream must not be empty")
	}
	known := make(map[string]bool, len(RsdnsTests))
	for _, test := range RsdnsTests {
		known[test.Name] = true
	}
	for _, name := range cfg.Tests {
		if !known[name] {
			return E2EConfig{}, fmt.Errorf("unknown test %q", name)
		}
	}
	for name := range cfg.Upstreams {
		if !known[name] {
			return E2EConfig{}, fmt.Errorf("unknown upstream type %q", name)
		}
	}
	return cfg, nil
}

// errSkip is a sentinel error that signals a test was skipped.
var errSkip = errors.New("SKIP")

func init() {
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.StringVar(&configPath, "config", "config.json", "E2E startup configuration")
	flag.Parse()

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	projectRoot = filepath.Join(wd, "../..")
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("[main] Starting rsdns E2E tests")
	log.Printf("[main] projectRoot=%s verbose=%v", projectRoot, verbose)
	var err error
	config, err = loadConfig(configPath)
	if err != nil {
		log.Fatalf("[main] load E2E config %s: %v", configPath, err)
	}
	log.Printf("[main] config=%s default_upstream=%s tests=%v", configPath, config.DefaultUpstream, config.Tests)

	rsdnsBin := filepath.Join(projectRoot, "target/debug/rsdns")
	if _, err := os.Stat(rsdnsBin); err != nil {
		rsdnsBin = filepath.Join(projectRoot, "target/release/rsdns")
		if _, err := os.Stat(rsdnsBin); err != nil {
			log.Fatalf("[main] rsdns binary not found at target/debug/rsdns or target/release/rsdns. Build first.")
		}
	}
	binaryPath = rsdnsBin
	log.Printf("[main] Using rsdns binary: %s", binaryPath)

	results := &TestResults{}

	for _, t := range RsdnsTests {
		if config.includes(t.Name) {
			runTest(results, "rsdns/"+t.Name, t.Fn)
		}
	}

	results.PrintSummary()

	if results.Failed > 0 {
		os.Exit(1)
	}
	log.Println("[main] All tests passed")
}

type TestResults struct {
	Passed  int
	Failed  int
	Skipped int
}

func (r *TestResults) PrintSummary() {
	fmt.Println("\n========================================")
	fmt.Println("TEST SUMMARY")
	fmt.Println("========================================")
	fmt.Printf("Passed:  %d\n", r.Passed)
	fmt.Printf("Failed:  %d\n", r.Failed)
	fmt.Printf("Skipped: %d\n", r.Skipped)
	fmt.Println("========================================")
}

func runTest(results *TestResults, name string, testFunc func() error) {
	fmt.Printf("\n========================================\n")
	fmt.Printf("TEST: %s\n", name)
	fmt.Printf("========================================\n")
	log.Printf("[run] START %s", name)

	start := time.Now()
	err := testFunc()
	elapsed := time.Since(start)

	if errors.Is(err, errSkip) {
		log.Printf("[run] SKIP %s (%.2fs)", name, elapsed.Seconds())
		results.Skipped++
	} else if err != nil {
		log.Printf("[run] FAIL %s (%.2fs): %v", name, elapsed.Seconds(), err)
		results.Failed++
	} else {
		log.Printf("[run] PASS %s (%.2fs)", name, elapsed.Seconds())
		results.Passed++
	}
}

var _ = context.Background
