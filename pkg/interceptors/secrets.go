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
	"context"
	"sync"
	"time"

	"github.com/napptive/grpc-jwt-go"
	"github.com/napptive/nerrors/pkg/nerrors"
	"github.com/napptive/njwt/pkg/config"
	"github.com/rs/zerolog/log"
)

const ClientTimeout = 30 * time.Second

// CachedSecret stores a JWT secret with the timestamp in which it has been retrieved.
type CachedSecret struct {
	timestamp time.Time
	secret    string
}

// Clone a cached secret.
func (cs *CachedSecret) Clone() *CachedSecret {
	return &CachedSecret{
		timestamp: cs.timestamp,
		secret:    cs.secret,
	}
}

// InterceptorZoneSecretManager offers a cached zone JWT signing secret retrieval interface. Elements
// retrieved from the SecretsClient are stored in an internal cache for a period of time before being evicted.
type InterceptorZoneSecretManager struct {
	sync.RWMutex
	// Config with the default signing secret. This is used for backward compatibility with old versions,
	// and it will be returned if the zone found in the JWT is empty.
	config        config.JWTConfig
	secretsClient grpc_jwt_go.SecretsClient
	zoneCacheTTL  time.Duration
	SecretCache   map[string]*CachedSecret
}

// NewInterceptorZoneSecretManager creates a zone manager that communicates with the secrets service
// to retrieve zone signing secrets.
func NewInterceptorZoneSecretManager(config config.JWTConfig, secretsClient grpc_jwt_go.SecretsClient, zoneCacheTTL time.Duration) SecretProvider {
	manager := &InterceptorZoneSecretManager{
		config:        config,
		secretsClient: secretsClient,
		zoneCacheTTL:  zoneCacheTTL,
		SecretCache:   make(map[string]*CachedSecret),
	}
	go manager.evictLoop()
	return manager
}

// evictLoop cleans the cache triggering the eviction method.
func (izsm *InterceptorZoneSecretManager) evictLoop() {
	ticker := time.NewTicker(izsm.zoneCacheTTL / 2)
	for range ticker.C {
		izsm.Evict()
	}
}

// Evict old entries of the cache attending to the creation timestamp.
func (izsm *InterceptorZoneSecretManager) Evict() {
	timeLimit := time.Now().Add(-1 * izsm.zoneCacheTTL)
	izsm.Lock()
	defer izsm.Unlock()
	for zoneID, secret := range izsm.SecretCache {
		if secret.timestamp.Before(timeLimit) {
			delete(izsm.SecretCache, zoneID)
		}
	}
}

// GetZoneSecret retrieves JWT signing secret associated with a given zone identifier.
func (izsm *InterceptorZoneSecretManager) GetZoneSecret(zoneID string) (*string, error) {
	izsm.RLock()
	secret, exists := izsm.SecretCache[zoneID]
	izsm.RUnlock()

	if exists {
		return &secret.secret, nil
	}

	if zoneID == "" && izsm.config.Secret != "" {
		// Preload the cache with the default secret
		izsm.Lock()
		izsm.SecretCache[""] = &CachedSecret{
			timestamp: time.Now(),
			secret:    izsm.config.Secret,
		}
		izsm.Unlock()
		return &izsm.config.Secret, nil
	}
	// Retrieve it from the secret provider
	ctx, cancel := context.WithTimeout(context.Background(), ClientTimeout)
	defer cancel()

	zoneSigningSecret, err := izsm.secretsClient.Get(ctx, &grpc_jwt_go.GetSecretRequest{SecretId: zoneID})
	if err != nil {
		log.Error().Err(err).Str("zone_id", zoneID).Msg("unable to retrieve zone signing secret")
		return nil, nerrors.NewInternalError("cannot verify token")
	}
	izsm.Lock()
	izsm.SecretCache[zoneID] = &CachedSecret{
		timestamp: time.Now(),
		secret:    zoneSigningSecret.JwtSecret,
	}
	izsm.Unlock()
	return &zoneSigningSecret.JwtSecret, nil
}
