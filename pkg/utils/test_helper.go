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
	"github.com/rs/xid"
	"syreclabs.com/go/faker"
)

// GetTestUserId returns a random UserId
func GetTestUserId() string {
	return xid.New().String()
}

// GetTestAccountId returns a random AccountId
func GetTestAccountId() string {
	return xid.New().String()
}

// GetTestEnvironmentId returns a random EnvironmentId
func GetTestEnvironmentId() string {
	return xid.New().String()
}

// GetTestUserName returns a random Username
func GetTestUserName() string {
	return faker.Internet().UserName()
}

func GetTestAccountName() string {
	return faker.Internet().UserName()
}
