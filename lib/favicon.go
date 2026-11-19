package lib

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/R0X4R/pinaak/pkg"
	"github.com/spaolacci/murmur3"
)

var (
	shodanBaseURL = "https://api.shodan.io"
	fofaBaseURL   = "https://fofa.info"
)

// FetchFavicon downloads the favicon.ico bytes from the target domain.
func FetchFavicon(domain string, timeoutSec int) ([]byte, error) {
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   time.Duration(timeoutSec) * time.Second,
		Transport: transport,
	}

	schemes := []string{"https", "http"}
	for _, scheme := range schemes {
		targetURL := fmt.Sprintf("%s://%s/favicon.ico", scheme, domain)
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", pkg.RandomUserAgent())

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			data, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			_ = resp.Body.Close()
			if err == nil && len(data) > 0 {
				return data, nil
			}
		} else {
			_ = resp.Body.Close()
		}
	}

	return nil, fmt.Errorf("could not retrieve favicon from %s", domain)
}

// CalculateFaviconHash computes Shodan-compatible 32-bit MurmurHash3 for favicon bytes.
func CalculateFaviconHash(iconBytes []byte) int32 {
	encoded := base64.StdEncoding.EncodeToString(iconBytes)

	// Format base64 into lines of 76 characters ending with newline
	var buffer bytes.Buffer
	chunkSize := 76
	length := len(encoded)

	for i := 0; i < length; i += chunkSize {
		end := i + chunkSize
		if end > length {
			end = length
		}
		buffer.WriteString(encoded[i:end])
		buffer.WriteString("\n")
	}

	h := murmur3.New32()
	_, _ = h.Write(buffer.Bytes())
	return int32(h.Sum32())
}

// SearchFaviconQueries searches Shodan and FOFA for hosts matching the favicon hash.
func SearchFaviconQueries(domain string, hash int32, shodanKey string, fofaEmail string, fofaKey string, cdnChecker *CDNChecker, timeoutSec int) ([]pkg.ResultCandidate, error) {
	var candidates []pkg.ResultCandidate
	seenIP := make(map[string]bool)

	httpClient := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	// 1. Query Shodan if key is supplied
	if shodanKey != "" {
		shodanQuery := fmt.Sprintf("http.favicon.hash:%d", hash)
		endpoint := fmt.Sprintf("%s/shodan/host/search?key=%s&query=%s", shodanBaseURL, url.QueryEscape(shodanKey), url.QueryEscape(shodanQuery))
		resp, err := httpClient.Get(endpoint)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				var shodanResult struct {
					Matches []struct {
						IPStr string `json:"ip_str"`
					} `json:"matches"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&shodanResult); err == nil {
					for _, match := range shodanResult.Matches {
						ip := match.IPStr
						if ip == "" || seenIP[ip] {
							continue
						}
						seenIP[ip] = true

						isCDN, _, _ := cdnChecker.CheckIP(ip)
						if !isCDN {
							candidates = append(candidates, pkg.ResultCandidate{
								Domain:   domain,
								OriginIP: ip,
								Method:   "favicon-hash",
								Details:  fmt.Sprintf("shodan favicon hash %d", hash),
							})
						}
					}
				}
			}
			_ = resp.Body.Close()
		}
	}

	// 2. Query FOFA if credentials are supplied
	if fofaEmail != "" && fofaKey != "" {
		fofaQuery := fmt.Sprintf("icon_hash=\"%d\"", hash)
		qbase64 := base64.StdEncoding.EncodeToString([]byte(fofaQuery))
		endpoint := fmt.Sprintf("%s/api/v1/search/all?email=%s&key=%s&qbase64=%s", fofaBaseURL, url.QueryEscape(fofaEmail), url.QueryEscape(fofaKey), url.QueryEscape(qbase64))
		resp, err := httpClient.Get(endpoint)
		if err == nil {
			if resp.StatusCode == http.StatusOK {
				var fofaResult struct {
					Results [][]string `json:"results"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&fofaResult); err == nil {
					for _, row := range fofaResult.Results {
						if len(row) > 1 {
							ip := row[1]
							if ip == "" || seenIP[ip] {
								continue
							}
							seenIP[ip] = true

							isCDN, _, _ := cdnChecker.CheckIP(ip)
							if !isCDN {
								candidates = append(candidates, pkg.ResultCandidate{
									Domain:   domain,
									OriginIP: ip,
									Method:   "favicon-hash",
									Details:  fmt.Sprintf("fofa favicon hash %d", hash),
								})
							}
						}
					}
				}
			}
			_ = resp.Body.Close()
		}
	}

	return candidates, nil
}
