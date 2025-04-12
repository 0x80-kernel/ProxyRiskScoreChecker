// internal/logging/logging.go
package logging

type LogType int

const (
	LogSuccess LogType = iota
	LogError
	LogQuestion
	LogInfo
)

type Logger interface {
	Log(logType LogType, format string, args ...interface{})
}
