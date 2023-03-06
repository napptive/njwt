/**
 * Copyright 2023 Napptive
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
	"github.com/golang/mock/gomock"
	grpc_jwt_go "github.com/napptive/grpc-jwt-go"
	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
	"time"
)

var _ = ginkgo.Describe("Zone aware secrets manager", func() {

	testCacheTTL := 5 * time.Second
	jwtConfig := GetTestJWTConfig()
	var ctrl *gomock.Controller
	var secretsClientMock *MockSecretsClient
	var secretsManager SecretProvider

	ginkgo.BeforeEach(func() {
		ctrl = gomock.NewController(ginkgo.GinkgoT())
		secretsClientMock = NewMockSecretsClient(ctrl)
		secretsManager = NewInterceptorZoneSecretManager(jwtConfig, secretsClientMock, testCacheTTL)
	})

	ginkgo.It("should be able to return the default JWT secret for backward compatibility", func() {
		secret, err := secretsManager.GetZoneSecret("")
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(*secret).Should(gomega.Equal(jwtConfig.Secret))
	})

	ginkgo.It("should be able to retrieve a zone secret", func() {
		response := &grpc_jwt_go.SecretResponse{
			JwtSecret: "zoneSecet",
		}
		secretsClientMock.EXPECT().Get(gomock.Any(), gomock.Any()).Return(response, nil)
		secret, err := secretsManager.GetZoneSecret("uncached")
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(*secret).Should(gomega.Equal(response.JwtSecret))
		newSecret, err := secretsManager.GetZoneSecret("uncached")
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(*newSecret).Should(gomega.Equal(response.JwtSecret))
	})

	ginkgo.It("should be able to retrieve a zone secret after eviction", func() {
		response := &grpc_jwt_go.SecretResponse{
			JwtSecret: "zoneSecet",
		}
		secretsClientMock.EXPECT().Get(gomock.Any(), gomock.Any()).Return(response, nil).Times(2)
		secret, err := secretsManager.GetZoneSecret("uncached")
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(*secret).Should(gomega.Equal(response.JwtSecret))
		time.Sleep(2 * testCacheTTL)
		newSecret, err := secretsManager.GetZoneSecret("uncached")
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(*newSecret).Should(gomega.Equal(response.JwtSecret))
	})

})
