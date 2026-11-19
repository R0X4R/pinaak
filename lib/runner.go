package lib

import (
	"context"
	"fmt"
	"sync"

	"github.com/R0X4R/pinaak/pkg"
)

// Execute orchestrates origin discovery and candidate verification.
func Execute(ctx context.Context, opts *pkg.Options) error {
	cdnChecker, err := NewCDNChecker()
	if err != nil {
		return fmt.Errorf("failed to initialize CDN checker: %w", err)
	}

	var candidates []ResultCandidate
	seenCandidates := make(map[string]bool)

	addCandidate := func(c ResultCandidate) {
		key := fmt.Sprintf("%s:%s", c.Domain, c.OriginIP)
		if !seenCandidates[key] {
			seenCandidates[key] = true
			candidates = append(candidates, c)
		}
	}

	// 1. Process user-supplied subdomains from file or stdin (if provided)
	subList := opts.SubdomainsList
	if subList == "" && opts.Domain == "" && pkg.HasStdin() {
		subList = "-"
	}
	subdomains, err := ReadSubdomains(subList)
	if err == nil && len(subdomains) > 0 {
		pkg.PrintInfo("Loaded %d input subdomains for range filtering", len(subdomains))
		subCandidates, err := ExtractNonCDNCandidates(subdomains, cdnChecker, opts.Threads, opts.Timeout)
		if err == nil {
			for _, c := range subCandidates {
				addCandidate(c)
			}
			pkg.PrintInfo("Found %d non-CDN candidate IPs from input subdomains", len(subCandidates))
		}
	}

	// 2. Process target domain techniques (if -d specified)
	var baseline *BaselineResponse
	if opts.Domain != "" {
		pkg.PrintInfo("Analyzing domain: %s", opts.Domain)

		// Fetch baseline response through public CDN for verification comparison
		if !opts.SkipVerification {
			b, bErr := FetchBaseline(opts.Domain, opts.Timeout)
			if bErr == nil {
				baseline = b
				pkg.PrintInfo("Captured baseline (status: %d, title: %q)", b.StatusCode, b.Title)
			}
		}

		// Check Mail and DNS records
		mailHits, err := CheckDNSHistoryAndMail(opts.Domain, opts.SecurityTrailsKey, cdnChecker, opts.Timeout)
		if err == nil && len(mailHits) > 0 {
			for _, c := range mailHits {
				addCandidate(c)
			}
			pkg.PrintInfo("Found %d candidate IPs from mail/DNS history", len(mailHits))
		}

		// Check Favicon Hash
		iconBytes, err := FetchFavicon(opts.Domain, opts.Timeout)
		if err == nil {
			hash := CalculateFaviconHash(iconBytes)
			pkg.PrintInfo("Favicon MurmurHash3: %d", hash)
			favHits, err := SearchFaviconQueries(opts.Domain, hash, opts.ShodanKey, opts.FofaEmail, opts.FofaKey, cdnChecker, opts.Timeout)
			if err == nil && len(favHits) > 0 {
				for _, c := range favHits {
					addCandidate(c)
				}
				pkg.PrintInfo("Found %d candidate IPs from favicon search", len(favHits))
			}
		}

		// Check Certificate Search engines
		if (opts.CensysID != "" && opts.CensysSecret != "") || opts.ShodanKey != "" {
			certHits, err := SearchCertificates(opts.Domain, opts.CensysID, opts.CensysSecret, opts.ShodanKey, cdnChecker, opts.Timeout)
			if err == nil && len(certHits) > 0 {
				for _, c := range certHits {
					addCandidate(c)
				}
				pkg.PrintInfo("Found %d candidate IPs from certificate search", len(certHits))
			}
		}
	}

	if len(candidates) == 0 {
		pkg.PrintWarning("No non-CDN candidate IPs discovered")
		return nil
	}

	pkg.PrintInfo("Discovered %d candidate origin IPs. Starting verification...", len(candidates))

	// 3. Verify candidates concurrently
	if opts.SkipVerification {
		for _, c := range candidates {
			pkg.LogFinding(pkg.ResultEntry{
				Domain:     c.Domain,
				OriginIP:   c.OriginIP,
				Method:     c.Method,
				Confidence: "unverified",
				Details:    c.Details,
			})
		}
		return nil
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, opts.Threads)
	var confirmedCount int
	var mu sync.Mutex

	for _, cand := range candidates {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(c ResultCandidate) {
			defer wg.Done()
			defer func() { <-sem }()

			finding, ok := VerifyCandidateIP(ctx, c.Domain, c.OriginIP, c.Method, baseline, opts.Timeout)
			if ok && finding != nil {
				mu.Lock()
				confirmedCount++
				mu.Unlock()
				pkg.LogFinding(*finding)
			}
		}(cand)
	}

	wg.Wait()

	if confirmedCount == 0 {
		pkg.PrintWarning("Candidate IPs probed, but none matched the target application signature")
	} else {
		pkg.PrintSuccess("Origin discovery complete: %d verified origin IP(s) found", confirmedCount)
	}

	return nil
}
