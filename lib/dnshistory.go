package lib

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// ExtractMailRecords queries MX and SPF TXT records that often point directly to origin subnets.
func ExtractMailRecords(domain string, cdnChecker *CDNChecker, timeoutSec int) ([]ResultCandidate, error) {
	opts := dnsx.Options{
		BaseResolvers: []string{"1.1.1.1:53", "8.8.8.8:53"},
		MaxRetries:    2,
		QuestionTypes: []uint16{dns.TypeMX, dns.TypeTXT, dns.TypeA},
		Timeout:       time.Duration(timeoutSec) * time.Second,
	}

	client, err := dnsx.New(opts)
	if err != nil {
		return nil, fmt.Errorf("initializing dnsx for mail records failed: %w", err)
	}

	var candidates []ResultCandidate
	seen := make(map[string]bool)

	// 1. Check MX records
	mxHosts, err := client.Lookup(domain)
	if err == nil {
		for _, mxHost := range mxHosts {
			// Resolve MX host A records
			ips, err := client.Lookup(mxHost)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				if seen[ip] {
					continue
				}
				seen[ip] = true

				isCDN, _, _ := cdnChecker.CheckIP(ip)
				if !isCDN {
					candidates = append(candidates, ResultCandidate{
						Domain:   domain,
						OriginIP: ip,
						Method:   "mail-records",
						Details:  fmt.Sprintf("mx host %s", mxHost),
					})
				}
			}
		}
	}

	// 2. Check SPF TXT records for explicit ip4 definitions
	txtRecords, err := client.Lookup(domain)
	if err == nil {
		for _, txt := range txtRecords {
			if strings.Contains(txt, "v=spf1") {
				parts := strings.Fields(txt)
				for _, part := range parts {
					if strings.HasPrefix(part, "ip4:") {
						rawIP := strings.TrimPrefix(part, "ip4:")
						// Handle CIDR or single IP
						ipStr := rawIP
						if idx := strings.Index(rawIP, "/"); idx != -1 {
							ipStr = rawIP[:idx]
						}
						parsed := net.ParseIP(ipStr)
						if parsed != nil && !seen[ipStr] {
							seen[ipStr] = true
							isCDN, _, _ := cdnChecker.CheckIP(ipStr)
							if !isCDN {
								candidates = append(candidates, ResultCandidate{
									Domain:   domain,
									OriginIP: ipStr,
									Method:   "mail-records",
									Details:  fmt.Sprintf("spf directive %s", part),
								})
							}
						}
					}
				}
			}
		}
	}

	return candidates, nil
}

// QuerySecurityTrailsHistory fetches historical A records from SecurityTrails.
func QuerySecurityTrailsHistory(domain string, apiKey string, cdnChecker *CDNChecker, timeoutSec int) ([]ResultCandidate, error) {
	if apiKey == "" {
		return nil, nil
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	endpoint := fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain)
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("securitytrails api returned status %d", resp.StatusCode)
	}

	var responseData struct {
		Records []struct {
			Values []struct {
				IP string `json:"ip"`
			} `json:"values"`
		} `json:"records"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return nil, fmt.Errorf("decoding securitytrails response failed: %w", err)
	}

	var candidates []ResultCandidate
	seen := make(map[string]bool)

	for _, record := range responseData.Records {
		for _, val := range record.Values {
			ip := val.IP
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true

			isCDN, _, err := cdnChecker.CheckIP(ip)
			if err != nil || isCDN {
				continue
			}

			candidates = append(candidates, ResultCandidate{
				Domain:   domain,
				OriginIP: ip,
				Method:   "dns-history",
				Details:  "historical a record from securitytrails",
			})
		}
	}

	return candidates, nil
}

// CheckDNSHistoryAndMail combines historical DNS lookups and mail record analysis.
func CheckDNSHistoryAndMail(domain string, securityTrailsKey string, cdnChecker *CDNChecker, timeoutSec int) ([]ResultCandidate, error) {
	var combined []ResultCandidate
	seen := make(map[string]bool)

	mailCandidates, err := ExtractMailRecords(domain, cdnChecker, timeoutSec)
	if err == nil {
		for _, c := range mailCandidates {
			if !seen[c.OriginIP] {
				seen[c.OriginIP] = true
				combined = append(combined, c)
			}
		}
	}

	if securityTrailsKey != "" {
		historyCandidates, err := QuerySecurityTrailsHistory(domain, securityTrailsKey, cdnChecker, timeoutSec)
		if err == nil {
			for _, c := range historyCandidates {
				if !seen[c.OriginIP] {
					seen[c.OriginIP] = true
					combined = append(combined, c)
				}
			}
		}
	}

	return combined, nil
}
