/**
 * Copyright 2020 Napptive
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package interceptors

import (
	"context"

	"github.com/napptive/nerrors/pkg/nerrors"
	"github.com/napptive/njwt/pkg/config"
	"github.com/napptive/njwt/pkg/njwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	// UserIdKey with the name of the key that will be injected in the context metadata corresponding to the user identifier.
	UserIDKey = "user_id"
	// UsernameKey with the name of the key that will be injected in the context metadata corresponding to the username.
	UsernameKey = "username"
)

// WithServerJWTInterceptor creates a gRPC interceptor that verifies the JWT received is valid
func WithServerJWTInterceptor(config config.JWTConfig) grpc.ServerOption {
	return grpc.UnaryInterceptor(JwtInterceptor(config))

}

// JwtInterceptor verifies the JWT token and adds the claim information in the context
func JwtInterceptor(config config.JWTConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		authClaim, err := authorizeJWTToken(ctx, config)
		if err != nil {
			return nil, nerrors.FromError(err).ToGRPC()
		}

		// add the claim information to the context metadata
		md := metadata.New(map[string]string{UserIDKey: authClaim.UserID, UsernameKey: authClaim.Username})
		oldMD, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, nerrors.NewInternalError("error recovering metadata").ToGRPC()
		}
		// adds the new metadata to the old one
		fullMD := metadata.Join(oldMD, md)
		// and create new context with this one
		newCtx := metadata.NewIncomingContext(ctx, fullMD)

		return handler(newCtx, req)
	}
}

// authorizeJWTToken checks the token and returns the authxClaim
func authorizeJWTToken(ctx context.Context, config config.JWTConfig) (*njwt.AuthxClaim, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nerrors.NewUnauthenticatedError("retrieving metadata failed")
	}

	token, ok := md[config.Header]
	if !ok {
		return nil, nerrors.NewUnauthenticatedError("no auth details supplied")
	}

	// Check the token and get the authx claim
	var pc njwt.AuthxClaim
	if _, err := njwt.New().Recover(token[0], config.Secret, &pc); err != nil {
		return nil, nerrors.NewUnauthenticatedError("error recovering token [%s]", err.Error())
	}

	return &pc, nil
}

// GetClaimFromContext gets user info from context
func GetClaimFromContext(ctx context.Context) (*njwt.AuthxClaim, error) {

	// check that the user id and username are in the metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nerrors.NewUnauthenticatedError("no metadata found")
	}
	userID, exists := md[UserIDKey]
	if !exists {
		return nil, nerrors.NewUnauthenticatedError("userId not found in metadata")
	}
	username, exists := md[UsernameKey]
	if !exists {
		return nil, nerrors.NewUnauthenticatedError("username not found in metadata").ToGRPC()
	}

	return &njwt.AuthxClaim{
		UserID:   userID[0],
		Username: username[0],
	}, nil
}
