# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] - 2026-01-17

### Fixed

- 🔧 Fixed GeoSite rules being stored to wrong category (twitter/facebook now correctly return FakeIP)
- 🔧 Fixed Forward plugin timeout configuration not being applied

### Changed

- ⚡ Reduced UDP single timeout from 2s to 500ms for faster race mode response
- ⚡ Reduced UDP retries from 2 to 1
- ⚡ Increased race mode concurrent upstreams from 3 to 5
- 📝 Updated README with architecture diagram, badges, and detailed examples
- 🎨 Added TitanDNS logo (SVG)

### Added

- 📝 Comprehensive bilingual documentation (English + Chinese)
- 📝 Detailed configuration examples in config.example.yaml
- 🔧 Troubleshooting workflow documentation

## [1.0.0] - 2026-01-10

- Initial public release of the minimal source set (online branch).
- Added CI build workflow for release artifacts with date-based naming.
- Added bilingual README and standard OSS docs.
- License set to Apache-2.0.
- Added tag-triggered GitHub Releases and one-click installer.
- Added Linux x86_64-v3 build target.
- Added release checksums and installer verification.
