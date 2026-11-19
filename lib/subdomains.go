package lib

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// ReadSubdomains reads lines from an input file or piped standard input.
func ReadSubdomains(filePath string) ([]string, error) {
	if filePath == "-" {
		return readLinesFromReader(os.Stdin)
	}
	if filePath != "" {
		return readLinesFromFile(filePath)
	}
	return nil, nil
}

func readLinesFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open subdomains file: %w", err)
	}
	defer file.Close()
	return readLinesFromReader(file)
}

func readLinesFromReader(r io.Reader) ([]string, error) {
	var lines []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip common URL prefixes if user passed full URLs
		line = strings.TrimPrefix(line, "https://")
		line = strings.TrimPrefix(line, "http://")
		if idx := strings.Index(line, "/"); idx != -1 {
			line = line[:idx]
		}
		if idx := strings.Index(line, ":"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)

		if line != "" && !seen[line] {
			seen[line] = true
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading input error: %w", err)
	}
	return lines, nil
}

// ResolveSubdomains queries DNS A records for each host using dnsx.
func ResolveSubdomains(hosts []string, threads int, timeoutSec int) (map[string][]string, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	opts := dnsx.Options{
		BaseResolvers: []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"},
		MaxRetries:    2,
		QuestionTypes: []uint16{dns.TypeA},
		Timeout:       time.Duration(timeoutSec) * time.Second,
	}

	client, err := dnsx.New(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize dnsx client: %w", err)
	}

	if threads <= 0 {
		threads = 25
	}

	results := make(map[string][]string)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			ips, err := client.Lookup(h)
			if err != nil || len(ips) == 0 {
				return
			}
			mu.Lock()
			results[h] = ips
			mu.Unlock()
		}(host)
	}

	wg.Wait()
	return results, nil
}

// ExtractNonCDNCandidates resolves subdomains and filters out CDN IP ranges.
func ExtractNonCDNCandidates(subdomains []string, cdnChecker *CDNChecker, threads int, timeout int) ([]ResultCandidate, error) {
	if len(subdomains) == 0 {
		return nil, nil
	}

	resolved, err := ResolveSubdomains(subdomains, threads, timeout)
	if err != nil {
		return nil, err
	}

	var candidates []ResultCandidate
	seenIP := make(map[string]bool)

	for host, ips := range resolved {
		for _, ip := range ips {
			if seenIP[ip] {
				continue
			}
			seenIP[ip] = true

			isCDN, _, err := cdnChecker.CheckIP(ip)
			if err != nil || isCDN {
				continue
			}

			candidates = append(candidates, ResultCandidate{
				Domain:   host,
				OriginIP: ip,
				Method:   "subdomain-resolution",
				Details:  fmt.Sprintf("resolved from non-proxied host %s", host),
			})
		}
	}

	return candidates, nil
}
