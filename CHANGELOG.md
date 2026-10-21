# Changelog

All notable changes to the Humifortis Keycloak Connector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **A failed sign-in through an external identity provider is reported against the integration**: Keycloak's
  `IDENTITY_PROVIDER_LOGIN_ERROR` (which has no user, no provider and no cause) becomes the event
  `identity_provider_login_failed` of `integration:keycloak`, naming the provider (read from the broker callback the listener
  is serving), the application and the address. Humifortis raises one operational alert per provider; it is never a failed
  password and moves nobody's risk.
- **The protocol of the sign-in** (`auth_method`: `openid-connect` or `saml`) is on the evaluation and on the decision report, so a SAML application's sign-in is decided and recorded like an OIDC one, with its protocol on the decision record (P10).
- **First brokered sign-in**: `first_broker_login` is `true` or `false` on every brokered evaluation (absent for a sign-in through the realm's own form), so a later sign-in is a known `false`, not an unknown.
- **Kinds of WebAuthn credential** (docs/sso-and-external-idp-e2e.spec.md, P9): the kind (`security_key`, `device_bound`,
  `synced`, `unknown`) is read from the backup flag the browser posts, at registration and at each step-up, and reported as
  `mfa_method_kind` with an opaque credential reference (`webauthn_credential`). The identity metadata lists the credentials
  held (`webauthn_credentials`). A WebAuthn registration (`UPDATE_CREDENTIAL`) is now reported as `mfa_token_enrolled`.
  When Humifortis accepts only a stronger kind (`required_factor_kind`), the step-up router refuses a weaker credential as
  a failed step-up.
- **Account source** (`account_source`) on every user event and on the evaluation: `local`, `ldap:<provider>`, `ad:<provider>`
  or `brokered:<alias>` (docs/sso-and-external-idp-e2e.spec.md, P8). Absent, never guessed, when the user cannot be resolved.
- **Federated account age**: for a user with a federation link, the directory's creation attribute comes first, Keycloak's
  import time only when the directory gives none (P6).
- **Directory outage**: a failed sign-in of a person the directory imported before, with no user resolved, is reported as
  `directory_unavailable` (with `directory` = the provider name), not as a failed password (P7).
- **Sign-in to a disabled account**: Keycloak's `user_disabled` login error (the password was right; Keycloak checks the
  enabled flag after it) is reported as `auth_account_disabled`, no longer as a failed sign-in counted as password guessing.
  It covers accounts disabled in Keycloak and, with a writable Active Directory federation, in the domain.
- **The step-up factor is decided by Humifortis** (`required_factor` of `/evaluate`, docs/assurance-and-factor-selection.spec.md): the
  router challenges it and no longer chooses for a generic step-up. `mfa_challenge_succeeded` / `_failed` carry `required_factor`
  beside `mfa_method`, so a degraded challenge is measurable.
- **SMS OTP step-up** (optional): `HUMIFORTIS_SMS_GATEWAY_URL` (+ `_TOKEN`, `HUMIFORTIS_SMS_PHONE_ATTRIBUTE`). A person without a verified
  email but with a number is texted through the operator's gateway; `SMS_OTP` is the last of the default fallback order.
- **Session check** required action (`humifortis-session-check`): evaluates a sign-in that reuses an SSO session; a deny or
  step-up ends the reused session. Enable it in Authentication → Required actions.

### Changed
- **Keycloak 26.8.1** is the one version the connector is built and tested against (was 23.0.3). No code change was
  needed; a Keycloak release with different extension APIs is served by a fork of the connector, not by this one.

### Fixed
- **The factor Humifortis resolved is the one carried out.** A passkey required of a person who has only an authenticator
  app is a TOTP step-up for Humifortis; the risk authenticator used the raw verdict and the router asked for an email code.
  It now applies `enforced_action`.
- **A wrong code of Keycloak's OTP form is a failed step-up**, no longer a failed password (it counted as credential
  guessing).
- **TOTP step-up**: the step-up router now runs Keycloak's own OTP form inside its step, as it already did for
  WebAuthn. Before, it delegated to an `auth-otp-form` placed next to it as ALTERNATIVE, which Keycloak ignores beside
  REQUIRED steps: a person with an authenticator app who was asked for TOTP ended on an error page. A person without
  a TOTP credential gets the email code instead. The MFA sub-flow needs no `auth-otp-form` any more (remove it).

### Added
- **Token exchange is evaluated** (optional, per client policy): the executor *humifortis-token-exchange-risk*, same behaviour
  as the refresh stage.
- **Refresh tokens are evaluated** (optional, per client policy): the executor *humifortis-token-refresh-risk* refuses a
  refresh on a deny or a step-up (`invalid_grant` / `humifortis_risk`); fail-open, nothing refused in `dry_run` / `shadow`.
- **Password grant is evaluated** (optional): *Humifortis Direct Grant Risk*, a step for the Direct grant flow. A deny or a
  step-up refuses the token (`401 humifortis_risk`); fail-open on no answer, nothing refused in `dry_run` / `shadow`.
- **Brokered logins report their identity provider**: `identity_provider` is the real alias (it was always `local`), and
  `first_broker_login` marks the first login with a provider.
- **A step-up that no factor answered is reported.** When Humifortis asks for a second factor and the person is signed in
  with none (the realm has no MFA sub-flow), the connector logs the misconfiguration and sends a second decision report for
  the flow (`outcome=allow`, `divergence=step_up_not_executed`) instead of leaving "step_up" as the last word. INSTALLATION.md
  now documents the MFA sub-flow.
- **Local decision source** (`HUMIFORTIS_DECISION_SOURCE=local`, or *Decision source* on the risk authenticator for one
  flow): the connector asks for the evaluation context (`/evaluate?include=context`), writes it into the authentication
  session (allowlisted, bounded, rewritten at every evaluation) and the realm's own flow decides, with the conditions
  *Humifortis high risk* (now with an `outcome`: `step_up` or `deny`), *risk level at least*, *rule fired* and
  *attribute equals*. An explicit deny and a lock of the account are still enforced by the connector, whatever the flow
  contains. A response without a usable context behaves as the `server` source (`context_missing`). The new last step
  *Humifortis decision report* reports what the flow did (`decision_source=local`). `scripts/install_local_decision_flow.py`
  creates the default flow. Nothing changes for realms that do not opt in.
- The step-up router does not ask again when a second factor already completed in the session: flows that reach it
  through several conditional sub-flows challenge the person once.
- The step-up condition matches (asks for a challenge) when no Humifortis note is present at all, instead of letting the
  person through: a flow that runs the condition without the risk authenticator before it is no longer an open door.

- **Round trip time**, forwarded as `rtt_ms` with `rtt_source`. When the reverse proxy in front of Keycloak sets
  `X-Edge-RTT-Ms` (whole milliseconds, e.g. nginx `$tcpinfo_rtt`) the connector forwards it (`edge`; also for
  `client_credentials`); the proxy must set the header itself (overwriting a client-sent one) and withhold it behind a CDN
  or tunnel, like the client IP it travels with. With no such proxy the device collector times four uncached requests to
  Keycloak and submits the shortest (`browser`, login evaluation and event stream only; the browser's own value also
  travels as `rtt_browser_ms` when the edge's is the one in `rtt_ms`; costs the collector step about four
  round trips). Nothing to configure; neither source, nothing sent.
- **Throttle enforcement**: the CAEP receiver accepts the Humifortis `throttle` event and sets the user's native
  Keycloak lockout (`failedLoginNotBefore`) until the stated deadline: monotonic (never shortened), lifted by an
  explicit `lifted` event, reported `ignored: realm_bruteforce_disabled` when the realm has brute-force detection off.
  A `LOGIN_ERROR` refused by the lockout (`user_temporarily_disabled`) is no longer reported as a failed login, so a
  throttle cannot feed the detector that created it. No new setting.
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
