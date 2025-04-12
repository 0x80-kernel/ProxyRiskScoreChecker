// internal/models/models.go
package models

import "context"

type ProxyValidator interface {
	ValidateProxy(ctx context.Context, proxy string) bool
}
