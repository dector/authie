# Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Session token length configurable through `Config.SessionTokenLength` field

## [0.2.0] - 2025-08-13

### Removed
- Removed IP address field from User and Session structs for enhanced privacy
- Updated authentication flow to no longer log or store client IP addresses
- Modified database schema to remove ip_address columns from users and sessions tables

## [0.1.0] - 2025-08-12

### Added
- Initial release
- Core authentication functionality
