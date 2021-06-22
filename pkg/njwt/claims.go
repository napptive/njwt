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
	"github.com/napptive/njwt/pkg/config"
	"github.com/rs/zerolog/log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

//Claim is the basic standard Claim
type Claim struct {
	jwt.StandardClaims
	// PersonalClaim contains the related information with the Napptive platform.
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
	// UserID internal napptive user identifier.
	UserID string
	// Username is the unique name of the user, currently the github account name.
	Username         string
	// AccountID with the actual account identifier
	AccountID        string
	// EnvironmentID with the actual environment identifier
	EnvironmentID    string
	// AccountAdmin with the admin account
	AccountAdmin     string
	// EnvironmentAdmin with the admin environment
	EnvironmentAdmin string
}

func (ac *AuthxClaim) ToMap () map[string]string{
	return map[string]string{config.UserIDKey: ac.UserID, config.UsernameKey: ac.Username,
		config.AccountIDKey: ac.AccountID, config.EnvironmentIDKey: ac.EnvironmentID,
		config.AccountAdminKey: ac.AccountAdmin, config.EnvironmentAdminKey: ac.EnvironmentAdmin,
	}
}

// NewAuthxClaim creates a new instance of AuthxClaim.
func NewAuthxClaim(userID string, username string, accountID string, environmentID string,
	accountAdmin string, environmentAdmin string) *AuthxClaim {
	return &AuthxClaim{
		UserID:           userID,
		Username:         username,
		AccountID:        accountID,
		EnvironmentID:    environmentID,
		AccountAdmin:     accountAdmin,
		EnvironmentAdmin: environmentAdmin,
	}
}

func (a AuthxClaim) Print() {
	log.Info().Str("userID", a.UserID).Str("username", a.Username).
		Str("AccountID", a.AccountID).Str("EnvironmentID", a.EnvironmentID).
		Str("AccountAdmin", a.AccountAdmin).Str("EnvironmentAdmin", a.EnvironmentAdmin).
		Msg("AuthxClaim")
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
