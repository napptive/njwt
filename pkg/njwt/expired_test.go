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

	"github.com/onsi/ginkgo"
	"github.com/onsi/gomega"
)

var _ = ginkgo.Describe("Expiration tests", func() {
	tokenMgr := New()
	secret := "secret"

	ginkgo.It("Test a token that has not expired", func() {
		claim := NewClaim("tt", time.Hour, nil)
		token, err := tokenMgr.Generate(claim, secret)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(token).NotTo(gomega.BeNil())

		expired, err := IsTokenExpired(*token)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(*expired).To(gomega.BeFalse())
	})
	ginkgo.It("Test a token that has expired", func() {
		claim := NewClaim("tt", time.Second, nil)
		token, err := tokenMgr.Generate(claim, secret)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(token).NotTo(gomega.BeNil())

		expired, err := IsTokenExpired(*token)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(*expired).To(gomega.BeTrue())
	})
	ginkgo.It("Test a token that has expired using a custom margin", func() {
		claim := NewClaim("tt", time.Hour, nil)
		token, err := tokenMgr.Generate(claim, secret)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(token).NotTo(gomega.BeNil())

		expired, err := IsTokenExpired(*token, time.Hour)
		gomega.Expect(err).To(gomega.Succeed())
		gomega.Expect(*expired).To(gomega.BeTrue())
	})
})
