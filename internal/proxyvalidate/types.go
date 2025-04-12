// internal/proxyvalidate/types.go
package proxyvalidate

import (
	"ProxyRiskScoreChecker/internal/logging"
	"time"
)

type ProxyValidator struct {
	ValidationTimeout time.Duration
	logger            logging.Logger
	proxyConverter    ProxyConverter
}

type ProxyConverter interface {
	ConvertProxyFormat(proxy string) string
}
