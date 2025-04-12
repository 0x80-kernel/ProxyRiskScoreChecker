// internal/riskscore/riskscore.go
package riskscore

import (
	"ProxyRiskScoreChecker/internal/logging"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	IPInfoEndpoint  = "http://ipinfo.io/json"
	IPQSEndpointFmt = "https://ipqualityscore.com/api/json/ip/%s/%s?strictness=%s"
)

func NewRiskScoreService(requestTimeout time.Duration, logger logging.Logger, converter ProxyConverter) *RiskScoreService {
	return &RiskScoreService{
		RequestTimeout: requestTimeout,
		Logger:         logger,
		Converter:      converter,
	}
}

func (s *RiskScoreService) GetOutboundIP(ctx context.Context, proxy string) string {
	formattedProxy := s.Converter.ConvertProxyFormat(proxy)
	if formattedProxy == "" {
		return ""
	}
	s.Logger.Log(logging.LogInfo, "Using formatted proxy: %s", formattedProxy)
	proxyURL, err := url.Parse(formattedProxy)
	if err != nil {
		s.Logger.Log(logging.LogError, "Failed to parse proxy URL: %v", err)
		return ""
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: s.RequestTimeout,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, IPInfoEndpoint, nil)
	if err != nil {
		s.Logger.Log(logging.LogError, "Failed to create request: %v", err)
		return ""
	}
	s.Logger.Log(logging.LogInfo, "Sending request to %s through proxy", IPInfoEndpoint)
	response, err := client.Do(req)
	if err != nil {
		s.Logger.Log(logging.LogError, "Failed to get external IP for proxy %s: %v", proxy, err)
		return ""
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		s.Logger.Log(logging.LogError, "Failed to get external IP for proxy %s: HTTP status %d", proxy, response.StatusCode)
		return ""
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		s.Logger.Log(logging.LogError, "Failed to read response body: %v", err)
		return ""
	}
	var ipInfo struct {
		IP string `json:"ip"`
	}
	err = json.Unmarshal(body, &ipInfo)
	if err != nil {
		s.Logger.Log(logging.LogError, "Failed to parse JSON response: %v", err)
		return ""
	}
	if ipInfo.IP == "" {
		s.Logger.Log(logging.LogError, "Could not retrieve external IP for proxy %s", proxy)
		return ""
	}
	s.Logger.Log(logging.LogSuccess, "Successfully detected IP %s for proxy", ipInfo.IP)
	return ipInfo.IP
}

func (s *RiskScoreService) CheckIPRiskScore(ctx context.Context, ipAddress, apiKey, strictnessLevel string) int {
	url := fmt.Sprintf(IPQSEndpointFmt, apiKey, ipAddress, strictnessLevel)
	client := &http.Client{
		Timeout: s.RequestTimeout,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		s.Logger.Log(logging.LogError, "Failed to create request: %v", err)
		return -1
	}
	response, err := client.Do(req)
	if err != nil {
		s.Logger.Log(logging.LogError, "Failed to check IP quality for %s: %v", ipAddress, err)
		return -1
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		s.Logger.Log(logging.LogError, "Failed to query IPQS API for IP %s: HTTP status %d", ipAddress, response.StatusCode)
		return -1
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		s.Logger.Log(logging.LogError, "Failed to read response body: %v", err)
		return -1
	}
	var ipqsResponse struct {
		Success    bool   `json:"success"`
		Message    string `json:"message"`
		FraudScore int    `json:"fraud_score"`
	}
	err = json.Unmarshal(body, &ipqsResponse)
	if err != nil {
		s.Logger.Log(logging.LogError, "Failed to parse JSON response: %v", err)
		return -1
	}
	if !ipqsResponse.Success {
		s.Logger.Log(logging.LogError, "Failed to query IPQS API for IP %s: %s", ipAddress, ipqsResponse.Message)
		return -1
	}
	return ipqsResponse.FraudScore
}

func (s *RiskScoreService) FilterProxies(proxyList []string, apiKey, strictnessLevel string) []string {
	var filteredProxies []string
	ctx := context.Background()
	for _, proxy := range proxyList {
		s.Logger.Log(logging.LogInfo, "Checking proxy: %s", proxy)
		outboundIP := s.GetOutboundIP(ctx, proxy)
		if outboundIP == "" {
			s.Logger.Log(logging.LogError, "Skipping proxy %s as external IP could not be determined", proxy)
			continue
		}
		s.Logger.Log(logging.LogInfo, "Detected outbound IP: %s", outboundIP)
		riskScore := s.CheckIPRiskScore(ctx, outboundIP, apiKey, strictnessLevel)
		if riskScore == 0 {
			s.Logger.Log(logging.LogSuccess, "Proxy %s has risk score 0", proxy)
			filteredProxies = append(filteredProxies, proxy)
		} else if riskScore >= 0 {
			s.Logger.Log(logging.LogInfo, "Proxy %s has risk score %d (skipped)", proxy, riskScore)
		}
	}
	return filteredProxies
}
