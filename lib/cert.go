package lib

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/R0X4R/pinaak/pkg"
)

// SearchCensysCertificates queries the Censys v2 Hosts API for certificates matching the target domain.
func SearchCensysCertificates(domain string, censysID string, censysSecret string, cdnChecker *CDNChecker, timeoutSec int) ([]pkg.ResultCandidate, error) {
	if censysID == "" || censysSecret == "" {
		return nil, nil
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	query := fmt.Sprintf("names: %s", domain)
	endpoint := fmt.Sprintf("https://search.censys.io/api/v2/hosts/search?q=%s&per_page=50", url.QueryEscape(query))

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating censys request failed: %w", err)
	}
	req.SetBasicAuth(censysID, censysSecret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pinaak/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("censys api returned status %d", resp.StatusCode)
	}

	var responseData struct {
		Result struct {
			Hits []struct {
				IP string `json:"ip"`
			} `json:"hits"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return nil, fmt.Errorf("decoding censys response failed: %w", err)
	}

	var candidates []pkg.ResultCandidate
	seen := make(map[string]bool)

	for _, hit := range responseData.Result.Hits {
		ip := hit.IP
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true

		isCDN, _, err := cdnChecker.CheckIP(ip)
		if err != nil || isCDN {
			continue
		}

		candidates = append(candidates, pkg.ResultCandidate{
			Domain:   domain,
			OriginIP: ip,
			Method:   "censys-cert",
			Details:  fmt.Sprintf("certificate subject match for %s", domain),
		})
	}

	return candidates, nil
}

// SearchShodanCertificates queries the Shodan API for hosts serving an SSL certificate matching the domain.
func SearchShodanCertificates(domain string, shodanKey string, cdnChecker *CDNChecker, timeoutSec int) ([]pkg.ResultCandidate, error) {
	if shodanKey == "" {
		return nil, nil
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	query := fmt.Sprintf("ssl:\"%s\"", domain)
	endpoint := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", url.QueryEscape(shodanKey), url.QueryEscape(query))

	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan api returned status %d", resp.StatusCode)
	}

	var responseData struct {
		Matches []struct {
			IPStr string `json:"ip_str"`
		} `json:"matches"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
		return nil, fmt.Errorf("decoding shodan response failed: %w", err)
	}

	var candidates []pkg.ResultCandidate
	seen := make(map[string]bool)

	for _, match := range responseData.Matches {
		ip := match.IPStr
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true

		isCDN, _, err := cdnChecker.CheckIP(ip)
		if err != nil || isCDN {
			continue
		}

		candidates = append(candidates, pkg.ResultCandidate{
			Domain:   domain,
			OriginIP: ip,
			Method:   "shodan-cert",
			Details:  fmt.Sprintf("shodan ssl certificate match for %s", domain),
		})
	}

	return candidates, nil
}

// SearchCertificates aggregates certificate origin discovery across available engines.
func SearchCertificates(domain string, censysID string, censysSecret string, shodanKey string, cdnChecker *CDNChecker, timeoutSec int) ([]pkg.ResultCandidate, error) {
	var combined []pkg.ResultCandidate
	seen := make(map[string]bool)

	if censysID != "" && censysSecret != "" {
		censysHits, err := SearchCensysCertificates(domain, censysID, censysSecret, cdnChecker, timeoutSec)
		if err == nil {
			for _, hit := range censysHits {
				if !seen[hit.OriginIP] {
					seen[hit.OriginIP] = true
					combined = append(combined, hit)
				}
			}
		}
	}

	if shodanKey != "" {
		shodanHits, err := SearchShodanCertificates(domain, shodanKey, cdnChecker, timeoutSec)
		if err == nil {
			for _, hit := range shodanHits {
				if !seen[hit.OriginIP] {
					seen[hit.OriginIP] = true
					combined = append(combined, hit)
				}
			}
		}
	}

	return combined, nil
}
