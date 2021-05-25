package interceptors

import (
	"context"
	"github.com/napptive/nerrors/pkg/nerrors"
	"google.golang.org/grpc/metadata"
)

func GetUserIDFromContext (ctx context.Context) (string, error) {
	// get the userId from the context
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", nerrors.NewInternalError("no metadata found").ToGRPC()
	}
	userID, exists := md[UserIDKey]
	if !exists {
		return "", nerrors.NewInternalError("userId not found in metadata")
	}
	return userID[0], nil
}

