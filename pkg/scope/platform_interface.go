package scope

import "context"

// PlatformClient is the interface all platform clients must implement
type PlatformClient interface {
	GetProgram(ctx context.Context, handle string) (*Program, error)
	ListPrograms(ctx context.Context) ([]*Program, error)
}
