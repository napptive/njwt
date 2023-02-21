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

package njwt

import (
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/napptive/njwt/pkg/helper"
	"github.com/rs/zerolog/log"
)

// Claim is the basic standard Claim
type Claim struct {
	jwt.StandardClaims
	// PersonalClaim contains the related information with the Napptive platform.
	PersonalClaim interface{} `json:"pc,omitempty"`
}

// NewClaim create a new Claim instance.
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
	Username string
	// AccountID with the actual account identifier
	AccountID string
	// AccountName with the name of the account
	AccountName string
	// EnvironmentID with the actual environment identifier
	EnvironmentID string
	// AccountAdmin with the admin account
	AccountAdmin bool
	// ZoneID with the zone identifier
	ZoneID string
	// ZoneURL with the base URL of the current zone.
	ZoneURL string
}

// ToMap transforms the claim into a key-value map.
func (ac *AuthxClaim) ToMap() map[string]string {
	return map[string]string{
		helper.UserIDKey:        ac.UserID,
		helper.UsernameKey:      ac.Username,
		helper.AccountNameKey:   ac.AccountName,
		helper.AccountIDKey:     ac.AccountID,
		helper.EnvironmentIDKey: ac.EnvironmentID,
		helper.AccountAdminKey:  strconv.FormatBool(ac.AccountAdmin),
		helper.ZoneIDKey:        ac.ZoneID,
		helper.ZoneURLKey:       ac.ZoneURL,
	}
}

// NewAuthxClaim creates a new instance of AuthxClaim.
func NewAuthxClaim(userID string, username string,
	accountID string, accountName string,
	environmentID string, accountAdmin bool,
	zoneID string, zoneURL string) *AuthxClaim {
	return &AuthxClaim{
		UserID:        userID,
		Username:      username,
		AccountID:     accountID,
		AccountName:   accountName,
		EnvironmentID: environmentID,
		AccountAdmin:  accountAdmin,
		ZoneID:        zoneID,
		ZoneURL:       zoneURL,
	}
}

// Print the contents of the claim through the logger.
func (ac *AuthxClaim) Print() {
	log.Info().Str("user_id", ac.UserID).Str("username", ac.Username).
		Str("account_id", ac.AccountID).Str("account_name", ac.AccountName).
		Str("environment_id", ac.EnvironmentID).Bool("account_admin", ac.AccountAdmin).Str("zone_id", ac.ZoneID).Str("zone_url", ac.ZoneURL).Msg("AuthxClaim")
}

// GetAuthxClaim returns the AuthxClaim section of the claim.
func (c *Claim) GetAuthxClaim() *AuthxClaim {
	return c.PersonalClaim.(*AuthxClaim)
}

// ExtendedAuthxClaim combining the standard and authx claims.
type ExtendedAuthxClaim struct {
	jwt.StandardClaims
	AuthxClaim
}

// RefreshClaim is the information stored to create the refresh token.
type RefreshClaim struct {
	UserID string
	// The tokenID is included to avoid in the future token control.
	TokenID string
}

// NewRefreshClaim create a new instance of RefreshClaim
func NewRefreshClaim(userID string, tokenID string) *RefreshClaim {
	return &RefreshClaim{UserID: userID, TokenID: tokenID}
}

// SignupClaim with information related to the signup process.
type SignupClaim struct {
	// ID with an internal identifier. This value can be used to retrieve data from the cache.
	ID string
	// OriginalUsername with the username in the target provider.
	OriginalUsername string
	// IdentityProvider with the credential provider with which the user logged into the platform
	IdentityProvider string
}

// NewSignupClaim builds a new claim for the signup process.
func NewSignupClaim(ID string, originalUsername string, identityProvider string) *SignupClaim {
	return &SignupClaim{
		ID:               ID,
		OriginalUsername: originalUsername,
		IdentityProvider: identityProvider,
	}
}

// ToMap transforms the signup claim into a map
func (sc *SignupClaim) ToMap() map[string]string {
	return map[string]string{
		helper.UserIDKey:      sc.ID,
		helper.UsernameKey:    sc.OriginalUsername,
		helper.AccountNameKey: sc.IdentityProvider,
	}
}
