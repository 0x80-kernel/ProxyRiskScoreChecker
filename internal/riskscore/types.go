// internal/riskscore/types.go
package riskscore

import (
	"ProxyRiskScoreChecker/internal/logging"
	"context"
	"time"
)

type RiskScoreValidator interface {
	GetOutboundIP(ctx context.Context, proxy string) string
	CheckIPRiskScore(ctx context.Context, ipAddress, apiKey, strictnessLevel string) int
	FilterProxies(proxyList []string, apiKey, strictnessLevel string) []string
}

type ProxyConverter interface {
	ConvertProxyFormat(proxy string) string
}

type RiskScoreService struct {
	RequestTimeout time.Duration
	Logger         logging.Logger
	Converter      ProxyConverter
}
