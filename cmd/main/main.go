// cmd/main/main.go
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"ProxyRiskScoreChecker/internal/logging"
	"ProxyRiskScoreChecker/internal/models"
	"ProxyRiskScoreChecker/internal/proxyvalidate"
	"ProxyRiskScoreChecker/internal/riskscore"
)

const (
	IPInfoEndpoint       = "http://ipinfo.io/json"
	IPQSEndpointFmt      = "https://ipqualityscore.com/api/json/ip/%s/%s?strictness=%s"
	InputProxiesFileName = "proxies.txt"
	OutputFileName       = "proxies_risk_score_0.txt"
	ValidProxiesFileName = "validproxys.txt"
	EnvAPIKey            = "API_KEY"
	RequestTimeout       = 10 * time.Second
	ValidationTimeout    = 5 * time.Second
)

type proxyLogger struct{}

func (l *proxyLogger) Log(logType logging.LogType, format string, args ...interface{}) {
	var prefix string
	switch logType {
	case logging.LogSuccess:
		prefix = "[+] "
	case logging.LogError:
		prefix = "[-] "
	case logging.LogQuestion:
		prefix = "[?] "
	case logging.LogInfo:
		prefix = "[*] "
	}
	message := fmt.Sprintf(format, args...)
	fmt.Println(prefix + message)
}

type proxyConverter struct{}

func (c *proxyConverter) ConvertProxyFormat(proxy string) string {
	host, port, user, password, protocol := ParseProxy(proxy)
	if host == "" || port == "" {
		return ""
	}
	if user != "" && password != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%s", protocol, user, password, host, port)
	}
	return fmt.Sprintf("%s://%s:%s", protocol, host, port)
}

type ProxyService struct {
	Validator      models.ProxyValidator
	RiskChecker    riskscore.RiskScoreValidator
	RequestTimeout time.Duration
	logger         logging.Logger
	converter      proxyvalidate.ProxyConverter
}

// NewProxyService creates a new service instance
func NewProxyService(logger logging.Logger) *ProxyService {
	converter := &proxyConverter{}
	validator := proxyvalidate.NewProxyValidator(
		ValidationTimeout,
		logger,
		converter,
	)
	riskChecker := riskscore.NewRiskScoreService(
		RequestTimeout,
		logger,
		converter,
	)
	return &ProxyService{
		Validator:      validator,
		RiskChecker:    riskChecker,
		RequestTimeout: RequestTimeout,
		logger:         logger,
		converter:      converter,
	}
}

func LogQuestionInput(logger logging.Logger, format string, args ...any) string {
	logger.Log(logging.LogQuestion, format, args...)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func GetAPIKey() (string, error) {
	apiKey := os.Getenv(EnvAPIKey)
	if apiKey == "" {
		return "", fmt.Errorf("API_KEY environment variable is not set. Please set it before running the application")
	}
	return apiKey, nil
}

func ReadProxiesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", filename, err)
	}
	defer file.Close()
	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			proxies = append(proxies, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning file %s: %v", filename, err)
	}
	return proxies, nil
}

func DetectProxyProtocol(logger logging.Logger, proxy string) string {
	proxy = strings.ToLower(proxy)
	if strings.HasPrefix(proxy, "http://") {
		return "http"
	} else if strings.HasPrefix(proxy, "https://") {
		return "https"
	} else if strings.HasPrefix(proxy, "socks5://") {
		return "socks5"
	}
	parts := strings.Split(proxy, ":")
	if len(parts) > 0 {
		switch parts[0] {
		case "http", "https", "socks5":
			return parts[0]
		}
	}
	logger.Log(logging.LogInfo, "No protocol detected for proxy %s, using HTTP as default", proxy)
	return "http"
}

func ParseProxy(proxy string) (host, port, user, password, protocol string) {
	proxy = strings.TrimSpace(proxy)
	protocolWithAuthPattern := regexp.MustCompile(`^(http|https|socks5)://(.+):(.+)@(.+):(\d+)$`)
	if match := protocolWithAuthPattern.FindStringSubmatch(proxy); match != nil {
		protocol = match[1]
		user = match[2]
		password = match[3]
		host = match[4]
		port = match[5]
		return
	}
	protocolNoAuthPattern := regexp.MustCompile(`^(http|https|socks5)://(.+):(\d+)$`)
	if match := protocolNoAuthPattern.FindStringSubmatch(proxy); match != nil {
		protocol = match[1]
		host = match[2]
		port = match[3]
		return
	}
	protocolPrefix := regexp.MustCompile(`^(http|https|socks5):/?/?`)
	if match := protocolPrefix.FindStringSubmatch(proxy); match != nil {
		protocol = match[1]
		proxy = protocolPrefix.ReplaceAllString(proxy, "")
	}
	userPassHostPattern := regexp.MustCompile(`^(.+):(.+)@(.+):(\d+)$`)
	if match := userPassHostPattern.FindStringSubmatch(proxy); match != nil {
		user = match[1]
		password = match[2]
		host = match[3]
		port = match[4]
		return
	}
	parts := strings.Split(proxy, ":")
	switch len(parts) {
	case 4:
		host = parts[0]
		port = parts[1]
		user = parts[2]
		password = parts[3]
	case 3:
		if parts[0] == "http" || parts[0] == "https" || parts[0] == "socks5" {
			protocol = parts[0]
			host = parts[1]
			port = parts[2]
		} else {
			host = parts[0]
			port = parts[1]
			user = parts[2]
		}
	case 2:
		host = parts[0]
		port = parts[1]
	default:
		return "", "", "", "", ""
	}
	if protocol == "" {
		protocol = "http"
	}
	return
}

func ConvertProxyFormat(logger logging.Logger, proxy string) string {
	host, port, user, password, protocol := ParseProxy(proxy)
	if host == "" || port == "" {
		logger.Log(logging.LogError, "Invalid proxy format (missing host or port): %s", proxy)
		return ""
	}
	logger.Log(logging.LogInfo, "Parsed proxy - Protocol: %s, Host: %s, Port: %s, Auth: %t",
		protocol, host, port, (user != "" && password != ""))
	if user != "" && password != "" {
		logger.Log(logging.LogInfo, "Using proxy with authentication")
		return fmt.Sprintf("%s://%s:%s@%s:%s", protocol, user, password, host, port)
	} else {
		logger.Log(logging.LogInfo, "Using proxy without authentication")
		return fmt.Sprintf("%s://%s:%s", protocol, host, port)
	}
}

func (s *ProxyService) ValidateAndSaveProxies(proxyList []string, filename string) ([]string, error) {
	var validProxies []string
	ctx := context.Background()
	for _, proxy := range proxyList {
		formattedProxy := s.converter.ConvertProxyFormat(proxy)
		if formattedProxy == "" {
			s.logger.Log(logging.LogError, "Invalid proxy format: %s", proxy)
			continue
		}
		if s.Validator.ValidateProxy(ctx, formattedProxy) {
			validProxies = append(validProxies, proxy)
		}
	}
	if err := saveProxiesToFile(validProxies, filename); err != nil {
		return nil, fmt.Errorf("failed to save proxies: %w", err)
	}
	return validProxies, nil
}

func prepareProxies(logger logging.Logger) ([]string, string, string, error) {
	apiKey, err := GetAPIKey()
	if err != nil {
		logger.Log(logging.LogError, "%v", err)
		logger.Log(logging.LogInfo, "Set the API_KEY environment variable with your IPQS API key")
		logger.Log(logging.LogInfo, "Example: export API_KEY=your_api_key_here")
		return nil, "", "", err
	}
	logger.Log(logging.LogSuccess, "API key loaded successfully from environment variable")
	strictnessLevel := LogQuestionInput(logger, "Enter strictness level (0-3) (leave blank for 0)")
	if strictnessLevel == "" {
		strictnessLevel = "0"
	}
	inputFileName := LogQuestionInput(logger, "Enter proxy file name (leave blank for default '%s')", InputProxiesFileName)
	if inputFileName == "" {
		inputFileName = InputProxiesFileName
	}
	proxyInput, err := ReadProxiesFromFile(inputFileName)
	if err != nil {
		logger.Log(logging.LogError, "Failed to read proxies from file: %v", err)
		return nil, "", "", err
	}
	logger.Log(logging.LogSuccess, "Successfully read %d proxies from %s", len(proxyInput), inputFileName)
	if len(proxyInput) == 0 {
		logger.Log(logging.LogError, "No proxies found in the file. Exiting.")
		return nil, "", "", fmt.Errorf("no proxies found in input file")
	}
	return proxyInput, apiKey, strictnessLevel, nil
}

func saveProxiesToFile(proxies []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filename, err)
	}
	defer file.Close()
	for _, proxy := range proxies {
		if _, err := file.WriteString(proxy + "\n"); err != nil {
			return fmt.Errorf("failed to write proxy: %v", err)
		}
	}
	return nil
}

func Run(logger logging.Logger) error {
	service := NewProxyService(logger)
	proxyInput, apiKey, strictnessLevel, err := prepareProxies(logger)
	if err != nil {
		return err
	}
	validProxies, err := service.ValidateAndSaveProxies(proxyInput, ValidProxiesFileName)
	if err != nil {
		return fmt.Errorf("%w", err)
	}
	if len(validProxies) == 0 {
		return fmt.Errorf("no valid proxies found")
	}
	filteredProxies := service.RiskChecker.FilterProxies(validProxies, apiKey, strictnessLevel)
	if err := saveProxiesToFile(filteredProxies, OutputFileName); err != nil {
		return err
	}
	logger.Log(logging.LogSuccess, "Found %d clean proxies", len(filteredProxies))
	return nil
}

func main() {
	logger := &proxyLogger{}
	logger.Log(logging.LogInfo, "Starting Proxy Risk Score Checker")
	if err := Run(logger); err != nil {
		logger.Log(logging.LogError, "Application error: %v", err)
		os.Exit(1)
	}
	logger.Log(logging.LogSuccess, "Operation completed successfully")
}
