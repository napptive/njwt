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
	UserId   = "user_id"
	Username = "username"
)

// WithServerJWTInterceptor creates a gRPC interceptor that verifies the JWT received is valid
func WithServerJWTInterceptor(config config.JWTConfig) grpc.ServerOption {
	return grpc.UnaryInterceptor(jwtInterceptor(config))

}

// jwtInterceptor verifies the JWT token and adds the claim information in the context
func jwtInterceptor(config config.JWTConfig) grpc.UnaryServerInterceptor {
	return func(ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler) (interface{}, error) {

		authClaim, err := authorizeJWTToken(ctx, config)
		if err != nil {
			return nil, nerrors.FromError(err).ToGRPC()
		}

		// add the claim information to the context metadata
		md := metadata.New(map[string]string{UserId: authClaim.UserID, Username: authClaim.Username})
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
		return nil, nerrors.NewInvalidArgumentError("retrieving metadata failed")
	}

	token, ok := md[config.Header]
	if !ok {
		return nil, nerrors.NewInvalidArgumentError("no auth details supplied")
	}

	// Check the token and get the authx claim
	var pc njwt.AuthxClaim
	if _, err := njwt.New().Recover(token[0], config.Secret, &pc); err != nil {
		return nil, nerrors.NewInvalidArgumentErrorFrom(err, "error recovering token")
	}

	return &pc, nil
}
