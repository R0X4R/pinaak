package lib

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/R0X4R/pinaak/pkg"
)

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)

// BaselineResponse stores fingerprint attributes of the public domain response.
type BaselineResponse struct {
	StatusCode    int
	Title         string
	ContentLength int64
	ServerHeader  string
}

// FetchBaseline retrieves baseline HTTP response attributes through the public CDN.
func FetchBaseline(domain string, timeoutSec int) (*BaselineResponse, error) {
	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	schemes := []string{"https", "http"}
	for _, scheme := range schemes {
		targetURL := fmt.Sprintf("%s://%s", scheme, domain)
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", RandomUserAgent())

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		if err != nil {
			continue
		}

		title := extractTitle(string(body))
		return &BaselineResponse{
			StatusCode:    resp.StatusCode,
			Title:         title,
			ContentLength: resp.ContentLength,
			ServerHeader:  resp.Header.Get("Server"),
		}, nil
	}

	return nil, fmt.Errorf("failed to fetch baseline for domain %s", domain)
}

// VerifyCandidateIP routes direct requests to the candidate IP with the domain in Host header.
func VerifyCandidateIP(domain string, ip string, method string, baseline *BaselineResponse, timeoutSec int) (*pkg.ResultEntry, bool) {
	dialer := &net.Dialer{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	// 1. Check TLS certificate presented directly on candidate IP port 443
	certMatches := checkTLSCertificate(domain, ip, timeoutSec)

	// 2. Direct HTTP probing with Host header
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, fmt.Sprintf("%s:443", ip))
		},
		TLSClientConfig: &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", domain), nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", RandomUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		// Fallback to plain HTTP on port 80
		return verifyCandidateHTTP(domain, ip, method, baseline, certMatches, timeoutSec)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, false
	}

	directTitle := extractTitle(string(body))
	confidence, confirmed := evaluateMatch(baseline, resp.StatusCode, directTitle, certMatches)
	if !confirmed {
		return nil, false
	}

	details := fmt.Sprintf("status: %d", resp.StatusCode)
	if certMatches {
		details += ", TLS cert match"
	}
	if directTitle != "" {
		details += fmt.Sprintf(", title: %q", directTitle)
	}

	return &pkg.ResultEntry{
		Domain:     domain,
		OriginIP:   ip,
		Method:     method,
		Confidence: confidence,
		Details:    details,
	}, true
}

func verifyCandidateHTTP(domain string, ip string, method string, baseline *BaselineResponse, certMatches bool, timeoutSec int) (*pkg.ResultEntry, bool) {
	dialer := &net.Dialer{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, fmt.Sprintf("%s:80", ip))
		},
	}

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: transport,
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", domain), nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("User-Agent", RandomUserAgent())

	resp, err := client.Do(req)
	if err != nil {
		if certMatches {
			return &pkg.ResultEntry{
				Domain:     domain,
				OriginIP:   ip,
				Method:     method,
				Confidence: "medium",
				Details:    "TLS cert matched on port 443 (HTTP refused)",
			}, true
		}
		return nil, false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return nil, false
	}

	directTitle := extractTitle(string(body))
	confidence, confirmed := evaluateMatch(baseline, resp.StatusCode, directTitle, certMatches)
	if !confirmed {
		return nil, false
	}

	details := fmt.Sprintf("port 80 status: %d", resp.StatusCode)
	if directTitle != "" {
		details += fmt.Sprintf(", title: %q", directTitle)
	}

	return &pkg.ResultEntry{
		Domain:     domain,
		OriginIP:   ip,
		Method:     method,
		Confidence: confidence,
		Details:    details,
	}, true
}

func checkTLSCertificate(domain string, ip string, timeoutSec int) bool {
	dialer := &net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:443", ip), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return false
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return false
	}

	leaf := certs[0]
	cleanDomain := strings.ToLower(domain)

	if strings.ToLower(leaf.Subject.CommonName) == cleanDomain {
		return true
	}
	for _, san := range leaf.DNSNames {
		cleanSAN := strings.ToLower(san)
		if cleanSAN == cleanDomain {
			return true
		}
		if strings.HasPrefix(cleanSAN, "*.") && strings.HasSuffix(cleanDomain, cleanSAN[1:]) {
			return true
		}
	}
	return false
}

func evaluateMatch(baseline *BaselineResponse, statusCode int, directTitle string, certMatches bool) (string, bool) {
	if certMatches {
		if baseline != nil && directTitle != "" && strings.EqualFold(directTitle, baseline.Title) {
			return "high", true
		}
		return "high", true
	}

	if baseline != nil && directTitle != "" && strings.EqualFold(directTitle, baseline.Title) {
		return "medium", true
	}

	if baseline != nil && statusCode == baseline.StatusCode && statusCode == http.StatusOK {
		return "medium", true
	}

	return "low", false
}

func extractTitle(body string) string {
	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
