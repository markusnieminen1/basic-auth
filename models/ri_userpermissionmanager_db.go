package models

import (
	"context"
)

type UserPermissionDatabase interface {
	// Permissions
	GetPathPermissions(ctx context.Context, userID int64) (paths []string, err error)
	GetOpsPermissions(ctx context.Context, userID int64) (operations []string, err error)
	AssignPathPermission(ctx context.Context, userID int64, path string) (err error)
	RevokePathPermission(ctx context.Context, userID int64, path string) (err error)
	AssignOpsPermission(ctx context.Context, userID int64, operation string) (err error)
	RevokeOpsPermission(ctx context.Context, userID int64, operation string) (err error)
}
