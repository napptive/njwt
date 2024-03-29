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
	"github.com/napptive/njwt/pkg/utils"
	"time"

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

// GenerateTestAuthxClaim returns a random AuthxClaim to use in the tests
func GenerateTestAuthxClaim() *AuthxClaim {
	accounts := make([]UserAccountClaim, 0)
	accounts = append(accounts, UserAccountClaim{
		Id:   utils.GetTestAccountId(),
		Name: utils.GetTestAccountName(),
		Role: "Admin",
	})
	return NewAuthxClaim(
		utils.GetTestUserId(),
		utils.GetTestUserName(),
		accounts[0].Id,
		accounts[0].Name,
		utils.GetTestEnvironmentId(),
		accounts[0].Role == "Admin",
		"zone_id",
		"zone_url",
		accounts)
}

var _ = ginkgo.Describe("njwt Token Manager tests", func() {
	ginkgo.Context("Check token manager generator", func() {
		tokenMgr := New()

		ginkgo.It("Check a normal lifecycle", func() {
			claim := NewClaim("tt", time.Hour, nil)
			secret := "secret"
			token, err := tokenMgr.Generate(claim, secret)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(token).NotTo(gomega.BeNil())

			recClaim, err := tokenMgr.Recover(*token, secret, nil)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(recClaim).NotTo(gomega.BeNil())
			gomega.Expect(recClaim).To(gomega.Equal(claim))
		})

		ginkgo.It("The recover secret is incorrect", func() {
			claim := NewClaim("tt", time.Hour, nil)
			secret := "secret"
			token, err := tokenMgr.Generate(claim, secret)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(token).NotTo(gomega.BeNil())

			recClaim, err := tokenMgr.Recover(*token, "notValidSecrete", nil)
			gomega.Expect(err).NotTo(gomega.Succeed())
			gomega.Expect(recClaim).To(gomega.BeNil())
		})

		ginkgo.It("The recover claim with personal claim", func() {

			pc := GenerateTestAuthxClaim()
			claim := NewClaim("tt", time.Hour, pc)

			secret := "secret"
			token, err := tokenMgr.Generate(claim, secret)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(token).NotTo(gomega.BeNil())

			recClaim, err := tokenMgr.Recover(*token, secret, &AuthxClaim{})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(recClaim).NotTo(gomega.BeNil())
			gomega.Expect(recClaim.PersonalClaim).To(gomega.BeAssignableToTypeOf(&AuthxClaim{}))
			gomega.Expect(recClaim.PersonalClaim).To(gomega.BeEquivalentTo(pc))
			recoveredPC, ok := recClaim.PersonalClaim.(*AuthxClaim)
			gomega.Expect(ok).To(gomega.BeTrue())
			gomega.Expect(recoveredPC).NotTo(gomega.BeNil())
			gomega.Expect(recoveredPC).To(gomega.Equal(pc))

		})
		ginkgo.It("The recover claim with refresh claim", func() {
			pc := NewRefreshClaim("userID", "tokenID")
			claim := NewClaim("tt", time.Hour, pc)

			secret := "secret"
			token, err := tokenMgr.Generate(claim, secret)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(token).NotTo(gomega.BeNil())

			recClaim, err := tokenMgr.Recover(*token, secret, &RefreshClaim{})
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(recClaim).NotTo(gomega.BeNil())
			gomega.Expect(recClaim.PersonalClaim).To(gomega.BeAssignableToTypeOf(&RefreshClaim{}))
			gomega.Expect(recClaim.PersonalClaim).To(gomega.BeEquivalentTo(pc))

		})
	})
	ginkgo.Context("working with unverified tokens", func() {
		tokenMgr := New()
		ginkgo.It("should be able to retrieve raw information from a token", func() {
			pc := GenerateTestAuthxClaim()
			claim := NewClaim("tt", time.Hour, pc)

			secret := "secret"
			token, err := tokenMgr.Generate(claim, secret)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(token).NotTo(gomega.BeNil())

			personalClaim := &AuthxClaim{}
			unverifiedClaim, err := tokenMgr.RecoverUnverified(*token, personalClaim)
			gomega.Expect(err).To(gomega.Succeed())
			gomega.Expect(unverifiedClaim).ShouldNot(gomega.BeNil())
			unverifiedAuthClaim := unverifiedClaim.GetAuthxClaim()
			gomega.Expect(unverifiedAuthClaim).ShouldNot(gomega.BeNil())
			gomega.Expect(unverifiedAuthClaim).Should(gomega.BeEquivalentTo(pc))
		})

	})
})
