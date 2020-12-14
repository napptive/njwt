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
	"time"

	"github.com/dgrijalva/jwt-go"
)

//Claim is the basic standard Claim
type Claim struct {
	jwt.StandardClaims
	PersonalClaim interface{} `json:"pc,omitempty"`
}

//NewClaim create a new Claim instance.
func NewClaim(issuer string, expiration time.Duration, pc interface{}) *Claim {
	ct := time.Now()
	standardClaim := jwt.StandardClaims{
		Id:        generateUUID(),
		Issuer:    issuer,
		IssuedAt:  ct.Unix(),
		NotBefore: ct.Unix(),
		ExpiresAt: ct.Add(expiration).Unix(),
	}
	return &Claim{StandardClaims: standardClaim, PersonalClaim: pc}
}

// AuthxClaim is the information stored by Authx in the claim.
type AuthxClaim struct {
	UserID   string
	Username string
}

// NewAuthxClaim creates a new instance of AuthxClaim.
func NewAuthxClaim(userID string, username string) *AuthxClaim {
	return &AuthxClaim{UserID: userID, Username: username}
}

// RefreshClaim is the information stored to create the refresh token.
type RefreshClaim struct {
	UserID string
	// The tokenID is included to avoid in the future token control.
	TokenID string
}

// NewRefreshClaim create a new instace of RefreshClaim
func NewRefreshClaim(userID string, tokenID string) *RefreshClaim {
	return &RefreshClaim{UserID: userID, TokenID: tokenID}
}