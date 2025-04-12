// internal/proxyvalidate/validate.go
package proxyvalidate

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"time"

	"ProxyRiskScoreChecker/internal/logging"
	"ProxyRiskScoreChecker/internal/models"
)

var _ models.ProxyValidator = (*ProxyValidator)(nil)

func NewProxyValidator(timeout time.Duration, logger logging.Logger, converter ProxyConverter) *ProxyValidator {
	return &ProxyValidator{
		ValidationTimeout: timeout,
		logger:            logger,
		proxyConverter:    converter,
	}
}

func (v *ProxyValidator) ValidateProxy(ctx context.Context, proxy string) bool {
	formattedProxy := v.proxyConverter.ConvertProxyFormat(proxy)
	if formattedProxy == "" {
		return false
	}
	validateCtx, cancel := context.WithTimeout(ctx, v.ValidationTimeout)
	defer cancel()
	proxyURL, err := url.Parse(formattedProxy)
	if err != nil {
		v.logger.Log(logging.LogError, "Failed to parse proxy URL: %v", err)
		return false
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: v.ValidationTimeout,
	}
	req, err := http.NewRequestWithContext(validateCtx, http.MethodGet, "http://httpbin.org/ip", nil)
	if err != nil {
		v.logger.Log(logging.LogError, "Failed to create validation request: %v", err)
		return false
	}
	v.logger.Log(logging.LogInfo, "Validating proxy: %s", proxy)
	response, err := client.Do(req)
	if err != nil {
		v.logger.Log(logging.LogError, "Proxy validation failed for %s: %v", proxy, err)
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		v.logger.Log(logging.LogError, "Proxy validation failed for %s: HTTP status %d", proxy, response.StatusCode)
		return false
	}
	v.logger.Log(logging.LogSuccess, "Proxy validation successful for %s", proxy)
	return true
}

func (v *ProxyValidator) ValidateAndSaveProxies(proxyList []string, outputFilename string) []string {
	var validProxies []string
	ctx := context.Background()
	v.logger.Log(logging.LogInfo, "Starting proxy validation for %d proxies...", len(proxyList))
	for _, proxy := range proxyList {
		if v.ValidateProxy(ctx, proxy) {
			validProxies = append(validProxies, proxy)
		}
	}
	v.logger.Log(logging.LogInfo, "Saving %d valid proxies to %s", len(validProxies), outputFilename)
	file, err := os.Create(outputFilename)
	if err != nil {
		v.logger.Log(logging.LogError, "Failed to create valid proxies file: %v", err)
		return validProxies
	}
	defer file.Close()
	for _, proxy := range validProxies {
		if _, err := file.WriteString(proxy + "\n"); err != nil {
			v.logger.Log(logging.LogError, "Failed to write to valid proxies file: %v", err)
			break
		}
	}
	v.logger.Log(logging.LogSuccess, "Successfully saved %d valid proxies to %s", len(validProxies), outputFilename)
	return validProxies
}
