package interceptors

import (
	"github.com/napptive/analytics/pkg/analytics"
	"github.com/napptive/analytics/pkg/entities"
	"google.golang.org/grpc"
	"time"

	"context"
)

func WithServerOpInterceptor(client analytics.Provider) grpc.ServerOption {
	return grpc.UnaryInterceptor(OpInterceptor(client))

}

// OpInterceptor sends the operation info call to the analytics provider
func OpInterceptor(client analytics.Provider) grpc.UnaryServerInterceptor {
	return func(ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		userID, err := GetUserIDFromContext(ctx)
		if err != nil {
			return nil, err
		}

		// Send the data to bigQuery
		client.SendOperationData(entities.OperationData{
			Timestamp: time.Now(),
			UserID:    userID,
			Operation: info.FullMethod,
		})

		return handler(ctx, req)
	}
}
