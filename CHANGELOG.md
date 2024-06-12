# Changelog

## [0.2.0](https://github.com/opiproject/sztp/compare/v0.1.1...v0.2.0) (2024-06-12)


### Features

* add helper script to extract keys ([1d1cd6c](https://github.com/opiproject/sztp/commit/1d1cd6cb9d7d75596fd000f26be903a419374c2e))
* add script to change boot image name ([1be3717](https://github.com/opiproject/sztp/commit/1be37173a729a35b78f8815433015a9d86e87c5a))
* add script to extract client binary from docker image ([635e4ec](https://github.com/opiproject/sztp/commit/635e4ec0e4c33c9c1da8b5bbd87bc507ce9d7af9))
* add script to fetch bootstrap logs ([4a31c3c](https://github.com/opiproject/sztp/commit/4a31c3c60c45ec23b875ede301a5dff7742a865c))
* add script to run just agent ([4be5a8e](https://github.com/opiproject/sztp/commit/4be5a8ed7547b81180d280ec7f5ba419eca62fad))
* expose dhclient.leases as argument ([9ab1fca](https://github.com/opiproject/sztp/commit/9ab1fca11dfe21e86e87a0392e1f5bb92a49091c))
* move images to their own folder ([c3b6908](https://github.com/opiproject/sztp/commit/c3b69084be223ee350d999b5a8c117ee79de8e6b))


### Bug Fixes

* 7080 was used for both redirecter and bootstrap ([c592b44](https://github.com/opiproject/sztp/commit/c592b44263ed1160fd93ba9afa8ef6c988a999e7))
* add deprecation note for docker-compose ([5135953](https://github.com/opiproject/sztp/commit/5135953e83ee4e67dcdd0706495d403b0a1d3f9c))
* add echo how to scp pem files to DPUs ([6cbe216](https://github.com/opiproject/sztp/commit/6cbe21637ec3e43ae18a48c9554d1ae84374141c))
* add small print for debug ([eea97cc](https://github.com/opiproject/sztp/commit/eea97cc30f9cd3d9f3d513a097319310e3b5efc8))
* add todo in the keys script to start using real iDEVid ([ff0906b](https://github.com/opiproject/sztp/commit/ff0906b542b5712fb5404d4eaec06058a832050c))
* add trust-anchor-cert to progress ([5461c97](https://github.com/opiproject/sztp/commit/5461c97dc1b0782d3d27ed643b5b0f6dfffb5705))
* **agent:** move certs to a folder, avoid root ([70fca4a](https://github.com/opiproject/sztp/commit/70fca4aa9f58febfb5640b7be70944c34ec1c973))
* **cert:** reuse bootstrap certs for web ([9ddcda3](https://github.com/opiproject/sztp/commit/9ddcda39060a23894fcb17eb4c174cda95cb93d7))
* **certs:** remove certs from client docker image ([a570359](https://github.com/opiproject/sztp/commit/a5703597db58d9246ba68c066abde27f5cd5a291))
* check for error in script ([bbd98d2](https://github.com/opiproject/sztp/commit/bbd98d2b0cf5bbd6ae87ef2df7de7669204af304))
* deprecate use of ioutil package ([56e79cd](https://github.com/opiproject/sztp/commit/56e79cd6be6e58d1b422755a8c3b9373b0cfc429))
* **deps:** update module github.com/jaypipes/ghw to v0.11.0 ([0171f80](https://github.com/opiproject/sztp/commit/0171f80ece4b9db5d93844531a668e5756011151))
* **deps:** update module github.com/jaypipes/ghw to v0.12.0 ([80ad341](https://github.com/opiproject/sztp/commit/80ad34153011cc123bde7134174253678e4151ba))
* **deps:** update module github.com/spf13/cobra to v1.7.0 ([a400c0b](https://github.com/opiproject/sztp/commit/a400c0b1d21c05b587b1ee86966feebf58d4fb5f))
* **deps:** update module github.com/twin/go-color to v1.4.0 ([c721d45](https://github.com/opiproject/sztp/commit/c721d45f8b7626236f7a994e0daaefab6e499ddd))
* **deps:** update module github.com/twin/go-color to v1.4.1 ([0c82913](https://github.com/opiproject/sztp/commit/0c8291304f08626b481b6abdd0903e24d2a9c323))
* handle ietf-restconf:errors ([cb997e9](https://github.com/opiproject/sztp/commit/cb997e95408d3f41ca888c3c89a4de10796a91ec))
* linter ([eb36730](https://github.com/opiproject/sztp/commit/eb36730b7998f34bf49e1742d7bc2065709a1a2d))
* linter issue ([b95621e](https://github.com/opiproject/sztp/commit/b95621ed2713773f2a01657859749f662820b345))
* linter switch case ([97858c3](https://github.com/opiproject/sztp/commit/97858c3ba47069eec2ae24038b5aca874e14dc74))
* pass real os-release file to container ([2857708](https://github.com/opiproject/sztp/commit/2857708551a7318a9abb4f959bb119cf3a7a4279))
* **progress:** add ssh-host-keys to reporting progress ([2c61991](https://github.com/opiproject/sztp/commit/2c61991c74ffcf5cfdfa863f07f89aa64d901e98))
* **progress:** remove redundant function argument ([98e0f42](https://github.com/opiproject/sztp/commit/98e0f42d7ef97bd1e98798c071d9738e02f65dfc))
* refactor simplify struct init code ([2dcd78c](https://github.com/opiproject/sztp/commit/2dcd78c01f044a027503e8f9856c04f87848aa6d))
* refactor simplify struct init code ([26c69db](https://github.com/opiproject/sztp/commit/26c69db19968197855fe891cd0a5c660844e9110))
* report more progress in new places ([5bb9036](https://github.com/opiproject/sztp/commit/5bb9036dd0d6e83b1b01aa723cd5fa58f474db31))
* shellcheck linter ([09b0602](https://github.com/opiproject/sztp/commit/09b0602203d47198abc564bf1aa558fdb1952fb3))
* small readme changes ([ac8b7bb](https://github.com/opiproject/sztp/commit/ac8b7bbdad37a2c7c092c652e47e9ac306c3382f))
* **sztp:** send ssh key when onboarding completed ([8f455c5](https://github.com/opiproject/sztp/commit/8f455c5d469e94c1a4e9efa1f51c5bbfe04bc6b0))
* use basename when changing boot image name ([478859f](https://github.com/opiproject/sztp/commit/478859f326309704fd890282a8bcbb30cb0fe3c9))
* **web:** copy client in addition to server certs ([484982c](https://github.com/opiproject/sztp/commit/484982c1e6fa7d5d4dbc0af9fcd82527a49c946f))
* **web:** enable SSLVerifyClient on web server ([25a1b90](https://github.com/opiproject/sztp/commit/25a1b906be2eddfd1e2c92337fe2ca5680cbe908)), closes [#342](https://github.com/opiproject/sztp/issues/342)
* **web:** switch to https ([ef66dd5](https://github.com/opiproject/sztp/commit/ef66dd5600f0a0db994bbc0e93eb6cae5f0365cd)), closes [#6](https://github.com/opiproject/sztp/issues/6)
