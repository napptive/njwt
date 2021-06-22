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
	"github.com/dgrijalva/jwt-go"
	"github.com/napptive/nerrors/pkg/nerrors"
	"github.com/napptive/njwt/pkg/config"
	"github.com/napptive/njwt/pkg/njwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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
		newCtx, err := addClaimToContext(authClaim, ctx)
		if err != nil {
			return nil, err
		}
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
	if token[0] == "" {
		return nil, nerrors.NewNotFoundError("error getting token. Log in to the platform")
	}

	// Check the token and get the authx claim
	var pc njwt.AuthxClaim
	if _, err := njwt.New().Recover(token[0], config.Secret, &pc); err != nil {
		castErr, ok := err.(*jwt.ValidationError)
		if !ok {
			return nil, nerrors.NewUnauthenticatedError("error recovering token [%s]", err.Error())
		}
		switch castErr.Errors {
		case jwt.ValidationErrorExpired:
			return nil, nerrors.NewUnauthenticatedError("[%s]. Please, log in to the platform again", err.Error())
		default:
			return nil, nerrors.NewUnauthenticatedError("error recovering token [%s]", err.Error())
		}

	}

	return &pc, nil
}

// addClaimToContext returns new Context joining the claim information
func addClaimToContext(authClaim *njwt.AuthxClaim, ctx context.Context) (context.Context, error) {
	// add the claim information to the context metadata
	md := metadata.New(authClaim.ToMap())
	oldMD, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nerrors.NewInternalError("error recovering metadata").ToGRPC()
	}
	// adds the new metadata to the old one
	fullMD := metadata.Join(oldMD, md)
	// and create new context with this one
	newCtx := metadata.NewIncomingContext(ctx, fullMD)

	return newCtx, nil
}

// GetClaimFromContext gets user info from context
func GetClaimFromContext(ctx context.Context) (*njwt.AuthxClaim, error) {

	// check that the user id and username are in the metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nerrors.NewUnauthenticatedError("no metadata found")
	}
	userID, exists := md[config.UserIDKey]
	if !exists {
		return nil, nerrors.NewUnauthenticatedError("userId not found in metadata")
	}
	username, exists := md[config.UsernameKey]
	if !exists {
		return nil, nerrors.NewUnauthenticatedError("username not found in metadata").ToGRPC()
	}

	// TODO: Launch an error if not exists
	accountIDVal := ""
	accountID, exists := md[config.AccountIDKey]
	if exists {
		accountIDVal = accountID[0]
	}
	envIDVal := ""
	envID, exists := md[config.EnvironmentIDKey]
	if exists {
		envIDVal = envID[0]
	}
	accountAdminVal := ""
	accountAdmin, exists := md[config.AccountAdminKey]
	if exists {
		accountAdminVal = accountAdmin[0]
	}
	envAdminVal := ""
	envAdmin, exists := md[config.EnvironmentAdminKey]
	if exists {
		envAdminVal = envAdmin[0]
	}
	return &njwt.AuthxClaim{
		UserID:           userID[0],
		Username:         username[0],
		AccountID:        accountIDVal,
		EnvironmentID:    envIDVal,
		AccountAdmin:     accountAdminVal,
		EnvironmentAdmin: envAdminVal,
	}, nil
}

func WithServerJWTStreamInterceptor(config config.JWTConfig) grpc.ServerOption {
	return grpc.StreamInterceptor(JwtStreamInterceptor(config))

}

// JwtStreamInterceptor verifies the JWT token and adds the claim information in the context
func JwtStreamInterceptor(config config.JWTConfig) grpc.StreamServerInterceptor {
	return func(srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler) error {

		ctx := stream.Context()
		authClaim, err := authorizeJWTToken(ctx, config)
		if err != nil {
			return nerrors.FromError(err).ToGRPC()
		}

		// add the claim information to the context metadata
		newCtx, err := addClaimToContext(authClaim, ctx)
		if err != nil {
			return err
		}
		// uses this new context in the stream wrapper
		w := newStreamContextWrapper(stream)
		w.SetContext(newCtx)
		return handler(srv, w)
	}
}
