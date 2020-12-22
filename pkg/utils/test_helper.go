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

package utils

import (
	"github.com/napptive/mockup-generator/pkg/mockups"
	"github.com/napptive/njwt/pkg/config"
	"github.com/napptive/njwt/pkg/njwt"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
	"time"
)

func GetAuthxClaimTest () *njwt.AuthxClaim {
	return njwt.NewAuthxClaim(mockups.GetUserId(), mockups.GetUserName())
}

func GetJWTConfigTest () config.JWTConfig {
	return config.JWTConfig{
		Secret: "mysecret",
		Header: "authorization",
	}
}

func CreateIncomingContext (header string, token string) context.Context {
	md := metadata.New(map[string]string{header: token})

	parentCtx, _ := context.WithTimeout(context.TODO(), time.Minute)
	return metadata.NewIncomingContext(parentCtx, md)
}

func CreateOutgoingContext (header string, token string) context.Context {
	md := metadata.New(map[string]string{header: token, "Prueba": "prueba"})

	parentCtx, _ := context.WithTimeout(context.TODO(), time.Minute)
	return metadata.NewOutgoingContext(parentCtx, md)
}