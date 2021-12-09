package interceptors

import (
	"context"
	"github.com/napptive/njwt/pkg/config"
	"github.com/napptive/njwt/pkg/njwt"
	"github.com/napptive/njwt/pkg/utils"
	"google.golang.org/grpc/metadata"
	"time"
)

// GetTestJWTConfig returns a JWTConfig to use in the tests
func GetTestJWTConfig() config.JWTConfig {
	return config.JWTConfig{
		Secret: "mysecret",
		Header: "authorization",
	}
}

// GetTestAuthxClaim returns a random AuthxClaim to use in the tests
func GetTestAuthxClaim () *njwt.AuthxClaim {
	return njwt.NewAuthxClaim(utils.GetTestUserId(), utils.GetTestUserName(),
		utils.GetTestAccountId(), utils.GetTestUserName(),
		utils.GetTestEnvironmentId(), false)
}

func CreateTestIncomingContext(header string, token string) (context.Context, context.CancelFunc) {
	md := metadata.New(map[string]string{header: token})

	parentCtx, cancel := context.WithTimeout(context.TODO(), time.Minute)
	return metadata.NewIncomingContext(parentCtx, md), cancel
}

func CreateTestOutgoingContext(header string, token string) (context.Context, context.CancelFunc) {
	md := metadata.New(map[string]string{header: token, "Test": "test"})

	parentCtx, cancel := context.WithTimeout(context.TODO(), time.Minute)
	return metadata.NewOutgoingContext(parentCtx, md), cancel
}