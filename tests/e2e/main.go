package main

import (
	"context"
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
)

// errSkip is a sentinel error that signals a test was skipped.
var errSkip = errors.New("SKIP")

func init() {
	flag.BoolVar(&verbose, "v", false, "verbose output")
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
		runTest(results, "rsdns/"+t.Name, t.Fn)
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
