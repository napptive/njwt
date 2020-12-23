
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

package config

import (
	"github.com/napptive/nerrors/pkg/nerrors"
	"github.com/rs/zerolog/log"
	"strings"
)

// JWT with the JWT configuration
type JWTConfig struct {
	// Secret with the token secret, used to recover the token
	Secret string
	// Header with the metadata field where the token is stored
	Header string
}

func NewJWTConfig (secret string, header string) JWTConfig {
	return JWTConfig{
		Secret: secret,
		Header: header,
	}
}

// IsValid checks if the configuration options are valid.
func (jc JWTConfig) IsValid () error {
	if jc.Secret == "" {
		return nerrors.NewInvalidArgumentError("secret must be filled")
	}
	if jc.Header == "" {
		return nerrors.NewInvalidArgumentError("header must be filled")
	}
	return nil
}

// Print the configuration using the application logger.
func (jc JWTConfig) Print () {
	log.Info().Str("header", jc.Header).
		Str("secret", strings.Repeat("*", len(jc.Secret))).Msg("Authorization")
}
