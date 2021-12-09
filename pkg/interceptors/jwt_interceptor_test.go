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
	"fmt"
	"github.com/napptive/njwt/pkg/helper"
	"net"
	"time"

	"github.com/napptive/grpc-ping-go"
	"github.com/napptive/nerrors/pkg/nerrors"
	"github.com/napptive/njwt/pkg/config"
	"github.com/napptive/njwt/pkg/njwt"
	"github.com/napptive/njwt/pkg/utils"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

// implement ping handler

type pingHandler struct{}

func (p pingHandler) Ping(ctx context.Context, request *grpc_ping_go.PingRequest) (*grpc_ping_go.PingResponse, error) {

	// check that the user id and username are in the metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nerrors.NewInternalError("no metadata found").ToGRPC()
	}
	_, exists := md[helper.UserIDKey]
	if !exists {
		return nil, nerrors.NewInternalError("userId not found in metadata").ToGRPC()
	}
	_, exists = md[helper.UsernameKey]
	if !exists {
		return nil, nerrors.NewInternalError("username not found in metadata").ToGRPC()
	}

	user, err := GetClaimFromContext(ctx)
	if err != nil {
		return nil, err
	}

	user.Print()

	// return the response
	return &grpc_ping_go.PingResponse{
		RequestNumber: request.RequestNumber,
		Data:          fmt.Sprintf("Ping [%d] received", request.RequestNumber),
	}, nil
}


// JWT authorize test
var _ = ginkgo.Describe("JWT interceptor", func() {
	ginkgo.It("check JWT Token is enabled", func() {
		authClaim := GetTestAuthxClaim()
		claim := njwt.NewClaim(utils.GetTestUserId(), time.Duration(1)*time.Hour, &authClaim)
		config := GetTestJWTConfig()

		token, err := njwt.New().Generate(claim, config.Secret)
		gomega.Expect(err).Should(gomega.Succeed())
		gomega.Expect(token).ShouldNot(gomega.BeNil())

		// Create a context with the token
		ctx := CreateTestIncomingContext(config.Header, *token)

		recovered, err := authorizeJWTToken(ctx, config)
		gomega.Expect(err).Should(gomega.Succeed())
		gomega.Expect(recovered.UserID).Should(gomega.Equal(authClaim.UserID))
		gomega.Expect(recovered.Username).Should(gomega.Equal(authClaim.Username))

	})

	ginkgo.It("check JWT Token is disabled", func() {
		authClaim := GetTestAuthxClaim()
		claim := njwt.NewClaim(utils.GetTestUserId(), time.Duration(1)*time.Hour*(-1), &authClaim)
		config := GetTestJWTConfig()

		token, err := njwt.New().Generate(claim, config.Secret)
		gomega.Expect(err).Should(gomega.Succeed())
		gomega.Expect(token).ShouldNot(gomega.BeNil())

		// Create a context with the token
		ctx := CreateTestIncomingContext(config.Header, *token)
		_, err = authorizeJWTToken(ctx, config)
		gomega.Expect(err).ShouldNot(gomega.Succeed())

	})

})

const (
	bufSize = 1024 * 1024
)

// JWT interceptor test
var _ = ginkgo.Context("Server interceptor", func() {

	var s *grpc.Server
	// gRPC test listener
	var lis *bufconn.Listener

	var client grpc_ping_go.PingServiceClient
	var config config.JWTConfig

	ginkgo.BeforeSuite(func() {
		lis = bufconn.Listen(bufSize)
		config = GetTestJWTConfig()
		s = grpc.NewServer(WithServerJWTInterceptor(config))

		handler := pingHandler{}
		grpc_ping_go.RegisterPingServiceServer(s, handler)
		go func() {
			if err := s.Serve(lis); err != nil {
				log.Fatal().Errs("Server exited with error: %v", []error{err})
				return
			}
		}()

		conn, err := grpc.DialContext(context.Background(), "bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return lis.Dial()
			}), grpc.WithInsecure())
		gomega.Expect(err).Should(gomega.Succeed())

		client = grpc_ping_go.NewPingServiceClient(conn)

	})
	ginkgo.AfterSuite(func() {
		s.Stop()
		lis.Close()
	})

	ginkgo.It("should not be able to call to handler.Ping without a token", func() {
		response, err := client.Ping(context.Background(), &grpc_ping_go.PingRequest{RequestNumber: 1})
		gomega.Expect(response).Should(gomega.BeNil())
		gomega.Expect(err).ShouldNot(gomega.Succeed())
	})

	ginkgo.It("should be able to call to handler.Ping with a valid token", func() {

		authClaim := GetTestAuthxClaim()
		claim := njwt.NewClaim(utils.GetTestUserId(), time.Duration(1)*time.Hour, &authClaim)
		config := GetTestJWTConfig()

		manager := njwt.New()
		token, err := manager.Generate(claim, config.Secret)
		gomega.Expect(err).Should(gomega.Succeed())
		gomega.Expect(token).ShouldNot(gomega.BeNil())

		// Create a context with the token
		ctx := CreateTestOutgoingContext(config.Header, *token)
		request := grpc_ping_go.PingRequest{RequestNumber: 1}
		response, err := client.Ping(ctx, &request)
		gomega.Expect(err).Should(gomega.Succeed())
		gomega.Expect(response).ShouldNot(gomega.BeNil())
		gomega.Expect(response.RequestNumber).Should(gomega.Equal(request.RequestNumber))
		gomega.Expect(response.Data).ShouldNot(gomega.BeEmpty())
	})

	ginkgo.It("should not be able to call to handler.Ping with a invalid token", func() {

		authClaim := GetTestAuthxClaim()
		claim := njwt.NewClaim(utils.GetTestUserId(), time.Minute*(-1), &authClaim)
		config := GetTestJWTConfig()

		manager := njwt.New()
		token, err := manager.Generate(claim, config.Secret)
		gomega.Expect(err).Should(gomega.Succeed())
		gomega.Expect(token).ShouldNot(gomega.BeNil())

		// Create a context with the token
		ctx := CreateTestOutgoingContext(config.Header, *token)

		_, err = client.Ping(ctx, &grpc_ping_go.PingRequest{RequestNumber: 1})
		gomega.Expect(err).ShouldNot(gomega.Succeed())
	})

	ginkgo.It("should not be able to call to handler.Ping with an empty token", func() {

		config := GetTestJWTConfig()

		token := ""

		// Create a context with the token
		ctx := CreateTestOutgoingContext(config.Header, token)

		_, err := client.Ping(ctx, &grpc_ping_go.PingRequest{RequestNumber: 1})
		gomega.Expect(err).ShouldNot(gomega.Succeed())

		nError := nerrors.FromGRPC(err)
		gomega.Expect(nError).ShouldNot(gomega.Succeed())
		gomega.Expect(nError.Code).Should(gomega.Equal(nerrors.NotFound))

	})

})
