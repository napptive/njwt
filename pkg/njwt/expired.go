/*
 Copyright 2021 Napptive

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

package njwt

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/napptive/nerrors/pkg/nerrors"
	"github.com/rs/zerolog/log"
)

const (
	// DefaultExpirationMargin with a time to subtract to the expiration date of a token.
	DefaultExpirationMargin = time.Minute
)

// IsTokenExpired checks the expiration date of a given raw token and determines if it
// has expired applying a margin.
// WARNING: This method does not check the signature of the token, so use it only if you
// understand the security downside.
func IsTokenExpired(rawToken string, margin ...time.Duration) (*bool, error) {
	parser := &jwt.Parser{}
	token, _, err := parser.ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims := token.Claims.(jwt.MapClaims)
	claimExpireTime, err := getExpirationTime(claims)
	if err != nil {
		return nil, err
	}
	effectiveExpirationTime := *claimExpireTime

	if len(margin) > 0 {
		effectiveExpirationTime = effectiveExpirationTime.Add(-margin[0])
	} else {
		effectiveExpirationTime = effectiveExpirationTime.Add(-DefaultExpirationMargin)
	}

	log.Debug().Str("claimExpireTime", claimExpireTime.String()).Str("effectiveExpirationTime", effectiveExpirationTime.String()).Msg("claims")

	result := time.Now().Unix() >= effectiveExpirationTime.Unix()
	return &result, nil
}

// getExpirationTime returns the expiration time of a given claim.
func getExpirationTime(claims jwt.MapClaims) (*time.Time, error) {
	rawExp, exists := claims["exp"]
	if !exists {
		return nil, nerrors.NewInvalidArgumentError("claims do not contain expiration (exp) field")
	}
	claimExpireTime := time.Unix(int64(rawExp.(float64)), 0)
	return &claimExpireTime, nil
}
