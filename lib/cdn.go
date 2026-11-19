package lib

import (
	"fmt"
	"net"

	"github.com/projectdiscovery/cdncheck"
)

// CDNChecker wraps the ProjectDiscovery cdncheck client for IP filtering.
type CDNChecker struct {
	client *cdncheck.Client
}

// NewCDNChecker instantiates a client pre-loaded with known CDN and WAF IP ranges.
func NewCDNChecker() (*CDNChecker, error) {
	client := cdncheck.New()
	if client == nil {
		return nil, fmt.Errorf("failed to initialize cdncheck client")
	}
	return &CDNChecker{client: client}, nil
}

// CheckIP determines whether an IP belongs to a CDN or WAF provider.
func (c *CDNChecker) CheckIP(ipStr string) (bool, string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, "", fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Check if IP is associated with a CDN provider
	if matched, provider, err := c.client.CheckCDN(ip); err == nil && matched {
		return true, provider, nil
	}

	// Check if IP is associated with a WAF provider
	if matched, provider, err := c.client.CheckWAF(ip); err == nil && matched {
		return true, provider, nil
	}

	// Check if IP is in general CDN or Cloud database
	if matched, provider, err := c.client.Check(ip); err == nil && matched {
		return true, provider, nil
	}

	return false, "", nil
}

// FilterCandidateIPs takes a list of IPs and separates non-CDN IPs from CDN IPs.
func (c *CDNChecker) FilterCandidateIPs(ips []string) ([]string, map[string]string) {
	candidates := make([]string, 0)
	cdnMap := make(map[string]string)
	seen := make(map[string]bool)

	for _, ip := range ips {
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true

		isCDN, provider, err := c.CheckIP(ip)
		if err != nil {
			continue
		}
		if isCDN {
			cdnMap[ip] = provider
		} else {
			candidates = append(candidates, ip)
		}
	}

	return candidates, cdnMap
}
