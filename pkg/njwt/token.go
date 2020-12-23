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

package njwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/rs/xid"
)

func generateUUID() string {
	return xid.New().String()
}

// TokenManager is an interface that generate new tokens.
type TokenManager interface {
	// Generate a new token with a claim.
	Generate(claim *Claim, secret string) (*string, error)
	// Recover the claim from a token, if you want to recover the personal claim yo must include the appropiated object.
	// Example: recoveredClaim, err := tokenMgr.Recover(*token, secret, &AuthxClaim{})
	Recover(tk string, secret string, pc interface{}) (*Claim, error)
}

// New create a new instance of the token generator.
func New() TokenManager {
	return &manager{}
}

type manager struct{}

// Generate a new token with a claim.
func (*manager) Generate(claim *Claim, secret string) (*string, error) {
	tk := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	tokenString, err := tk.SignedString([]byte(secret))
	if err != nil {
		return nil, err
	}
	return &tokenString, nil
}

// Recover the claim from a token, if you want to recover the personal claim yo must include the appropiated object.
// Example: recoveredClaim, err := tokenMgr.Recover(*token, secret, &AuthxClaim{})
func (*manager) Recover(tk string, secret string, pc interface{}) (*Claim, error) {

	claim := &Claim{PersonalClaim: pc}
	_, err := jwt.ParseWithClaims(tk, claim, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}
	return claim, nil

}