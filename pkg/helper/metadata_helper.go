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

package helper

const (
	// JWTID with the identifier of the JWT token.
	JWTID = "jwt_id"
	// JWTIssuedAt with the time in which the token was created.
	JWTIssuedAt = "jwt_issued_at"
	// UserIdKey with the name of the key that will be injected in the context metadata corresponding to the user identifier.
	UserIDKey = "user_id"
	// UsernameKey with the name of the key that will be injected in the context metadata corresponding to the username.
	UsernameKey = "username"
	// AccountIDKey with the name of the key that will be injected in the context metadata corresponding to the actual account identifier.
	AccountIDKey = "account_id"
	// AccountNameKey with the name of the key that will be injected in the context metadata corresponding to the actual account name.
	AccountNameKey = "account_name"
	// EnvironmentIDKey with the name of the key that will be injected in the context metadata corresponding to the actual environment identifier.
	EnvironmentIDKey = "environment_id"
	// AccountAdminKey with the name of the key that will be injected in the context metadata corresponding to the admin account identifier.
	AccountAdminKey = "account_admin"
	// ZoneIDKey with the name of the key that will be injected in the context metadata corresponding to the zone identifier.
	ZoneIDKey = "zone_id"
	// ZoneURLKey with the name of the key that will be injected in the context metadata corresponding to the zone url.
	ZoneURLKey = "zone_url"
	// IDKey with a common identifier key.
	IDKey = "id"
	// OriginalUsernameKey with the key that will be injected in the context metadata for signup claims corresponding with the orignal username in the target provider
	OriginalUsernameKey = "original_username"
	// IdentityProviderKey with the key that will be injected in the context metadata for signup claims corresponding with the the target provider
	IdentityProviderKey = "identity_provider"
)
