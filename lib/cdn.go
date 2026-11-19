package lib

import (
	"fmt"
	"net"

	"github.com/projectdiscovery/cdncheck"
)

// CDNChecker wraps the ProjectDiscovery cdncheck client for IP filtering.
type CDNChecker struct {
	client       *cdncheck.Client
	customRanges []*customRange
}

type customRange struct {
	ipNet    *net.IPNet
	provider string
}

var additionalCDNs = map[string][]string{
	"sucuri": {
		"192.88.134.0/23",
		"185.93.228.0/22",
		"192.124.249.0/24",
		"66.248.200.0/22",
		"2a02:fe80::/29",
	},
	"akamai": {
		"23.32.0.0/11",
		"23.192.0.0/11",
		"23.0.0.0/12",
		"104.64.0.0/10",
		"184.24.0.0/13",
		"184.84.0.0/14",
		"2.16.0.0/13",
		"96.6.0.0/15",
		"96.16.0.0/15",
		"173.222.0.0/15",
		"72.246.0.0/15",
		"88.221.0.0/16",
		"63.243.128.0/17",
		"2600:1400::/24",
	},
}

// NewCDNChecker instantiates a client pre-loaded with known CDN and WAF IP ranges.
func NewCDNChecker() (*CDNChecker, error) {
	client := cdncheck.New()
	if client == nil {
		return nil, fmt.Errorf("failed to initialize cdncheck client")
	}

	checker := &CDNChecker{client: client}
	for prov, cidrs := range additionalCDNs {
		for _, c := range cidrs {
			_, ipNet, err := net.ParseCIDR(c)
			if err == nil {
				checker.customRanges = append(checker.customRanges, &customRange{
					ipNet:    ipNet,
					provider: prov,
				})
			}
		}
	}
	return checker, nil
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

	// Check supplementary provider CIDR ranges
	for _, cr := range c.customRanges {
		if cr.ipNet.Contains(ip) {
			return true, cr.provider, nil
		}
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
