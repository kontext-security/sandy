# Changelog

## [0.1.10](https://github.com/kontext-security/sandy/compare/v0.1.9...v0.1.10) (2026-09-01)


### Features

* **cli:** ship Linux sandboxing ([#47](https://github.com/kontext-security/sandy/issues/47)) ([b6aa19b](https://github.com/kontext-security/sandy/commit/b6aa19b6903af6b5c16b70c8cea53be3ec6c0244))
* **linux:** prove the native enforcement substrate ([#45](https://github.com/kontext-security/sandy/issues/45)) ([ad20aca](https://github.com/kontext-security/sandy/commit/ad20acac2d977f3f8e397780f65557e412c082ef))
* **sandbox:** enforce current-process policies on Linux ([#46](https://github.com/kontext-security/sandy/issues/46)) ([cedf9be](https://github.com/kontext-security/sandy/commit/cedf9be9ba6bba8ed9fb44d1011d562c9273d5a3))


### Bug Fixes

* **cli:** classify oversized doctor output deterministically ([#49](https://github.com/kontext-security/sandy/issues/49)) ([9531e4b](https://github.com/kontext-security/sandy/commit/9531e4b65c97e37a0030f4650f7cec809b2b46d5))

## [0.1.9](https://github.com/kontext-security/sandy/compare/v0.1.8...v0.1.9) (2026-08-30)


### Features

* **cli:** add explicit executable grants and user profile files ([#41](https://github.com/kontext-security/sandy/issues/41)) ([0526d11](https://github.com/kontext-security/sandy/commit/0526d11f92b67cc6527e0b047aa3cbd62d1afbee))
* **sandbox:** accept versioned JSON policies ([#42](https://github.com/kontext-security/sandy/issues/42)) ([915ffda](https://github.com/kontext-security/sandy/commit/915ffda20646cf6a2963837f7554bf85121cdbd2))


### Code Refactoring

* **cli:** assemble policy before finalization ([#40](https://github.com/kontext-security/sandy/issues/40)) ([88c0cd3](https://github.com/kontext-security/sandy/commit/88c0cd388a29671578ebfd118fc8d62947da32be))
* **core:** centralize trusted policy finalization ([#39](https://github.com/kontext-security/sandy/issues/39)) ([a730487](https://github.com/kontext-security/sandy/commit/a730487f615f2e017750ebde5d30f4a908908ff5))

## [0.1.8](https://github.com/kontext-security/sandy/compare/v0.1.7...v0.1.8) (2026-08-30)


### Bug Fixes

* **release:** verify versions from Cargo metadata ([#37](https://github.com/kontext-security/sandy/issues/37)) ([ae31659](https://github.com/kontext-security/sandy/commit/ae316596b7c6f5584383d4efabaebf3079c059e6))

## [0.1.7](https://github.com/kontext-security/sandy/compare/v0.1.6...v0.1.7) (2026-08-30)


### Features

* add the current-process Rust sandbox API ([#34](https://github.com/kontext-security/sandy/issues/34)) ([e77c1b7](https://github.com/kontext-security/sandy/commit/e77c1b704aa6aae6ea7c5085ba5ce88a60c3faa2))


### Code Refactoring

* make the macOS CLI baseline explicit ([#33](https://github.com/kontext-security/sandy/issues/33)) ([8c0af2d](https://github.com/kontext-security/sandy/commit/8c0af2ddcbe25a7b67c4b8c56ce0a769204b809c))


### Build System

* publish the Rust sandbox packages ([#35](https://github.com/kontext-security/sandy/issues/35)) ([77c4ab4](https://github.com/kontext-security/sandy/commit/77c4ab41be2fad1f24dbc51f66e2a17915c0ea6e))


### Miscellaneous Chores

* prepare public Homebrew distribution ([#32](https://github.com/kontext-security/sandy/issues/32)) ([2f910a5](https://github.com/kontext-security/sandy/commit/2f910a50b004ee57ef16c7e3977ff2a0f5df893a))

## [0.1.6](https://github.com/kontext-security/sandy/compare/v0.1.5...v0.1.6) (2026-08-27)


### Features

* allow Numbat collector access on one local-host port ([#28](https://github.com/kontext-security/sandy/issues/28)) ([07c951b](https://github.com/kontext-security/sandy/commit/07c951bcc0fc1880333fac025b2cef5be660bd0f))
* preserve configured Numbat hooks ([#27](https://github.com/kontext-security/sandy/issues/27)) ([ca08d6b](https://github.com/kontext-security/sandy/commit/ca08d6b4a11c3437c1d99d6ca75d01cd701f0e07))
* set up runtime control integrations ([#30](https://github.com/kontext-security/sandy/issues/30)) ([b80339f](https://github.com/kontext-security/sandy/commit/b80339ffdec0f447bc2e0bbd0b1e2a3d8c3388be))

## [0.1.5](https://github.com/kontext-security/sandy/compare/v0.1.4...v0.1.5) (2026-08-23)


### Bug Fixes

* allow read-only macOS runtime timezone data ([#23](https://github.com/kontext-security/sandy/issues/23)) ([488b3f8](https://github.com/kontext-security/sandy/commit/488b3f85bbaa3aff1ca3b7f4262faa1ba30d3473))

## [0.1.4](https://github.com/kontext-security/sandy/compare/v0.1.3...v0.1.4) (2026-08-23)


### Bug Fixes

* preserve agent provider TLS trust ([#18](https://github.com/kontext-security/sandy/issues/18)) ([6b2daae](https://github.com/kontext-security/sandy/commit/6b2daae67aba06a54ff60242d91bce54fe344b00))

## [0.1.3](https://github.com/kontext-security/sandy/compare/v0.1.2...v0.1.3) (2026-08-23)


### Features

* allow exact Kontext socket access with --block-net ([#16](https://github.com/kontext-security/sandy/issues/16)) ([d56d78f](https://github.com/kontext-security/sandy/commit/d56d78f0f0db41674bf82d9205950ccb1175ad43))


### Bug Fixes

* preserve foreground terminal controls ([#14](https://github.com/kontext-security/sandy/issues/14)) ([d961399](https://github.com/kontext-security/sandy/commit/d96139979b1eea1a6084c839836516b38845153d))
* verify release tags without persisted credentials ([#12](https://github.com/kontext-security/sandy/issues/12)) ([5f3740a](https://github.com/kontext-security/sandy/commit/5f3740a845e6359712fc9ec14281d3e18df89bf0))

## [0.1.2](https://github.com/kontext-security/sandy/compare/v0.1.1...v0.1.2) (2026-08-23)


### Bug Fixes

* keep standalone runs independent of Kontext ([77587d3](https://github.com/kontext-security/sandy/commit/77587d3b0ceec67c60e7e460961038b1d770b0e5))
* publish releases to Homebrew tap ([d5520b6](https://github.com/kontext-security/sandy/commit/d5520b6eda2f057dfb4277bad6bbbd5b7136045a))

## [0.1.1](https://github.com/kontext-security/sandy/compare/v0.1.0...v0.1.1) (2026-08-22)


### Features

* add runtime control bridge for Kontext ([c3cb049](https://github.com/kontext-security/sandy/commit/c3cb04973186ea4ac2d76c09375819d6b9753676))
* data-driven agent profiles with explicit --profile selection ([b49782e](https://github.com/kontext-security/sandy/commit/b49782ec4073d6d1afa3731f62cf7db3107810a2))


### Bug Fixes

* address release-please updater review findings ([0581929](https://github.com/kontext-security/sandy/commit/05819292a45df067813615340e594e2fbc32523a))
* harden embedded agent profiles ([7d9e851](https://github.com/kontext-security/sandy/commit/7d9e85149a421388f4f8d12b8e74e6aabd380852))
* prepare formula for public distribution ([7e88d30](https://github.com/kontext-security/sandy/commit/7e88d30d044a0c3f899e8d5b8b8d146ba26e8a76))
* support inherited workspace versions ([502b034](https://github.com/kontext-security/sandy/commit/502b0349bb6e4ab6012efcc5a1113e7a2937fc79))
