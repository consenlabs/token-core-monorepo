# TokenCore Monorepo  

This repo holds some core code which support imToken. It contains 
- token-core, which manages the wallet keystore and sign signature by mobile phone
- imkey-core, which hold the private key in an imKey Hardwallet and sign signature security whitout leaks the pk to mobile.

## Getting Started
```bash
$ git clone git@github.com:consenlabs/token-core-monorepo.git
$ cargo build 
$ cargo test
```    
See more documents in the package readme  



## Packages
* `token-core` [token-core README](./token-core/README.md)
* `imkey-core` [imkey-core README](./imkey-core/README.md)



## Copyright and License

```
  Copyright 2023 imToken PTE. LTD.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
```