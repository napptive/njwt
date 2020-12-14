# NJWT
JWT library for the Napptive projects

The purpose of this project is to provide a simple JWT library to handle the authentication tokens of the Napptive platform.

## Usage

```go
     pc := NewAuthxClaim("userID", "username")
     claim := NewClaim("tt", time.Hour, pc)

     secret := "secret"
     token, err := tokenMgr.Generate(claim, secret)

     recoveredClaim, err := tokenMgr.Recover(*token, secret, &AuthxClaim{})
     recoveredPC, ok := recClaim.PersonalClaim.(*AuthxClaim)
```


## Badges

[![Maintainability](https://api.codeclimate.com/v1/badges/81607aa743e2644b935d/maintainability)](https://codeclimate.com/repos/5fd7b06e61ed8150ec009a16/maintainability) [![Test Coverage](https://api.codeclimate.com/v1/badges/81607aa743e2644b935d/test_coverage)](https://codeclimate.com/repos/5fd7b06e61ed8150ec009a16/test_coverage)

![Check changes in the Main branch](https://github.com/napptive/njwt/workflows/Check%20changes%20in%20the%20Main%20branch/badge.svg)

## License

 Copyright 2020 Napptive

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
