# Changelog

All notable changes to the Humifortis Keycloak Connector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Admin events by and on a service account**: an Admin API call made with a service account's token is reported with
  the service account as the actor (`service_account:…`, never a `user` for its internal service-account user). An admin
  event that changes a service account (role mapping on its user, client secret regeneration, client changes) carries
  `admin.change`, `admin.actor_type`, `admin.target_type` / `admin.target_id`, `admin.self_change` and, when the realm
  records representations, `admin.privileged_role`. Lookups are read-only and fail-open.
- `humifortis.owner` client attribute: forwarded as `service_account.owner` (who owns the client).
- **Service accounts**: a client authenticating with its own credentials (`client_credentials`;
  Keycloak `CLIENT_LOGIN` / `CLIENT_LOGIN_ERROR`) is now reported as a `service_account` entity
  (`service_account:keycloak:<realm>:<clientId>`, `entity_type` stated by the connector) with the
  event types `auth_login_success` / `auth_login_failed`. Before, these events were not forwarded.
  The context the service-account detectors need is resolved from the client's attributes
  (`humifortis.source_allowlist`, `humifortis.baseline_scopes`,
  `humifortis.expected_window_start_hour_utc` / `_end_hour_utc`, `humifortis.rotation_max_age_days`,
  and Keycloak's own `client.secret.creation.time`) and the request (IP, granted `scope`), and sent
  as `service_account.*` metadata. An undeclared or invalid expectation is not sent, so nothing is
  judged against a guess. See README, "Service accounts".
## [1.1.0] — 2026-10-03

### Added
- **Resilient API calls**: retries with jittered exponential backoff inside a login budget
  (`HUMIFORTIS_EVALUATE_BUDGET_MS`, default 1500 ms), one circuit breaker per endpoint (opens
  after 5 failed calls, single half-open probe, open time doubles up to 2 min), an
  `Idempotency-Key` / stable `event_id` on every attempt.
- **Event queue**: Keycloak events are buffered (`HUMIFORTIS_EVENT_QUEUE_SIZE`, default 10 000)
  and delivered once the API is back — no lost evidence during a blip.
- **Fallback policy**: a login without a decision follows the tenant's policy (allow / step-up /
  deny, privileged users separately), cached from every decision; `HUMIFORTIS_FALLBACK` overrides
  it. Every fallback is reported (`auth_decision_fallback`). The denial page says
  "temporarily unavailable" (HF-1001), not "suspicious".
- **Identity context**: effective roles (group-inherited, composites expanded, client roles as
  `clientId:role`), group paths, why a user is privileged (`privileged_reason`), configurable
  privileged roles/groups (realm attributes), account creation time (`account_created_at`,
  with an LDAP/AD attribute fallback). Collected once per request.
- **Application on the decision**: `client_id`, `client_name` and `redirect_uri` on `/evaluate`.
- **Client IP provenance**: `ip_source`, `proxy_headers_mode`, `proxy_trusted_addresses_set` on
  every event; a startup warning when proxy headers are believed from any peer.
- **WebAuthn step-up**: `REQUIRE_WEBAUTHN` runs Keycloak's WebAuthn ceremony for enrolled users.

### Fixed
- Privileged users through a group were not seen as privileged (direct role mappings only).
- `REQUIRE_WEBAUTHN` always degraded to an email code, even for users with a passkey.
- `is_privileged` was missing from listener events.
- Every failure path silently allowed the login (fail-open), unreported.

### Changed
- An administrator deleting or updating ANOTHER user is now the neutral `admin_user_action` (it was `delete_account` /
  `update_credential`, i.e. scored on the administrator as if they had deleted their own account).
- `HUMIFORTIS_TIMEOUT_MS` is the timeout of one attempt (default 800 ms); one configuration
  source for every component. `HUMIFORTIS_FALLBACK_ALLOW` is deprecated.

### Removed
- Unused `SaasClient` methods (`getRiskDecision`, `evaluate`, `sendBlockEventAsync`) and the
  `RiskDecision` / `SaasException` types.

## [1.0.0]

### Added
- Device signals on **failed logins**: add `scripts=js/humifortis-device.bundle.js` to the login
  theme's `theme.properties` (one line, any theme) and the device is collected on the login page
  itself — failed attempts carry it, which lets Humifortis detect one device trying several
  accounts. The short page after the password disappears. Optional; the flow is unchanged.
- Analyst responses from the Humifortis alert page, enforced here: RISC `account-disabled` (lock the
  account) and `credential-compromise` (require a new password), next to the existing CAEP
  `session-revoked`. **Opt-in per realm** (`hf.caep.enforce.accountDisabled`,
  `hf.caep.enforce.credentialCompromise`, both off by default); the receiver replies with what it did
  or why it did not.

### Fixed
- The device-collector script is served to **every** login theme (it ships in the jar's
  `theme-resources`). Before, a realm not using the `humifortis` theme got a 404 for the script
  and no device signals.
- `auth_credential_verified` events now carry `source: keycloak`.

### Changed
- Deployment is the jar only: no file to copy into a theme.
- Device signals are read and validated in one place (`DeviceSignals`) for every path.

### Removed
- `login.ftl.snippet` (superseded by the one-line theme setting) and the unused
  `HumifortisRBAAuthenticator` class.

## [1.0.0] - 2024-12-27

### Added
- Initial release of Humifortis Keycloak Connector
- Event listener SPI implementation for capturing authentication events
- RBA authenticator SPI implementation for risk-based access control
- Support for Keycloak 22.x, 23.x, and 24.x
- Comprehensive event monitoring for security-relevant events:
  - Login success/failure
  - Logout events
  - User registration
  - Password updates and resets
  - Email updates and verification
  - Token operations (refresh, revoke, introspect)
  - MFA (TOTP) changes
  - Account deletion
  - Admin operations
- Risk-based authentication with three actions:
  - ALLOW: Grant access immediately (risk 0-59)
  - CHALLENGE_MFA: Require additional authentication (risk 60-79)
  - BLOCK: Deny access with custom message (risk 80-100)
- Centralized configuration via environment variables
- Async event sending to minimize performance impact
- Fallback behavior when SaaS is unreachable
- Cross-system entity ID format for unified tracking
- Comprehensive documentation:
  - README with quick start guide
  - INSTALLATION guide with detailed setup instructions
  - API documentation
- Apache 2.0 license
- GitHub Actions CI/CD pipeline

### Architecture
- Thin client design (< 500 lines of core logic)
- No local policy engine or risk calculation
- All intelligence centralized in Humifortis SaaS
- RESTful API communication with SaaS platform
- Event-driven architecture for real-time monitoring

### Configuration
- `HUMIFORTIS_API_URL`: SaaS API endpoint
- `HUMIFORTIS_API_KEY`: API key for authentication
- `HUMIFORTIS_TIMEOUT_MS`: HTTP request timeout
- `HUMIFORTIS_FALLBACK_ALLOW`: Behavior when SaaS unreachable

### Technical Details
- Java 17+ compatibility
- Maven build system
- Keycloak SPI integration
- Gson for JSON processing
- Java 11+ HttpClient for HTTP communication
- JBoss Logging for diagnostics

## [Unreleased]

### Planned Features
- Enhanced logging and diagnostics
- Metrics export (Prometheus format)
- Health check endpoint
- Configuration validation
- Additional event types
- Performance optimizations
- Circuit breaker for SaaS communication
- Request retry logic
- Event batching for high-volume scenarios

[1.0.0]: https://github.com/humifortis/keycloak-connector/releases/tag/v1.0.0
