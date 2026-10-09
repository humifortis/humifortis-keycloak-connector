# Humifortis Keycloak Connector

**Version:** 1.0.0  
**License:** Apache 2.0  
**Supported Keycloak Versions:** 22.x, 23.x, 24.x  
**Java Version:** 17+

A thin client connector that integrates Keycloak with the Humifortis SaaS platform for centralized risk-based authentication (RBA) and security event monitoring.

## 🎯 Philosophy: Centralized Management

The Humifortis Keycloak Connector follows a **"thin client"** architecture where:

- ✅ **All intelligence lives in Humifortis SaaS** (risk calculation, policies, thresholds)
- ✅ **Connector is a dumb pipe** (capture events, query decisions, enforce actions)
- ✅ **Zero maintenance** (update policies in SaaS without touching Keycloak)
- ✅ **Cross-system correlation** (aggregate events from Keycloak, Okta, Auth0, custom apps)

### What the Connector Does

| Connector Responsibility | Humifortis SaaS Responsibility |
|-------------------------|-------------------------------|
| Capture events | Calculate risk scores |
| Send to SaaS | Define RBA policies |
| Query risk decisions | Set thresholds & rules |
| Enforce decisions | Aggregate cross-system events |
| **That's it!** | **Everything else** |

## 🚀 Quick Start (5 Minutes)

### Step 1: Register Connector in SaaS

1. Login to [https://humifortis.educosmic.tech](https://humifortis.educosmic.tech)
2. Go to: **Connectors → Add Connector**
3. Select: **Keycloak**
4. Name: "Production Keycloak"
5. Copy the generated API key: `humi_kc_prod_a1b2c3d4e5f6...`

### Step 2: Install in Keycloak

```bash
# Download the connector
wget https://github.com/humifortis/keycloak-connector/releases/latest/download/humifortis-keycloak-connector.jar

# Install to Keycloak providers directory
cp humifortis-keycloak-connector.jar /opt/keycloak/providers/

# Configure environment variables
export HUMIFORTIS_API_URL=https://api.humifortis.educosmic.tech
export HUMIFORTIS_API_KEY=humi_kc_prod_a1b2c3d4e5f6...

# Build and restart Keycloak
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

### Step 3: Enable in Keycloak Admin Console

1. **Enable Event Listener:**
   - Go to: **Realm Settings → Events → Event Listeners**
   - Check: `[✓] humifortis-event-listener`
   - Save

2. **Add to Authentication Flow:**
   - Go to: **Authentication → Flows → Browser**
   - Click **Add Step**
   - Select: "Humifortis Risk Authenticator" (after "Humifortis Device Collector" — see INSTALLATION.md, Step 6)
   - Place it after "Username Password Form"
   - Set requirement to **REQUIRED**
   - Save

3. **Test:**
   - Attempt a login
   - Check the Humifortis SaaS dashboard for events

**Done!** All configuration is now managed in the SaaS dashboard.

## 📋 Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HUMIFORTIS_API_URL` | No | `https://api.humifortis.educosmic.tech` | Humifortis SaaS API endpoint |
| `HUMIFORTIS_API_KEY` | **Yes** | - | API key from SaaS connector registration |
| `HUMIFORTIS_TIMEOUT_MS` | No | `800` | Timeout of one API attempt (ms) |
| `HUMIFORTIS_EVALUATE_BUDGET_MS` | No | `1500` | Longest a login waits for a decision, retries included (ms) |
| `HUMIFORTIS_FALLBACK` | No | (tenant policy) | `allow` \| `step_up` \| `deny` when Humifortis cannot answer — overrides the tenant policy (see INSTALLATION.md, Resilience) |
| `HF_CAEP_ENABLED` | No | `false` | Enable CAEP/SSF receiver (`POST /realms/{realm}/ssf/caep/events`) |
| `HF_CAEP_ISSUER` | No | - | Trusted Humifortis SET issuer (`iss`) |
| `HF_CAEP_AUDIENCE` | No | - | Expected audience (`aud`) |
| `HF_CAEP_JWKS_URI` | No | - | JWKS URI used to verify Humifortis asymmetric signatures |
| `HF_CAEP_CLOCK_SKEW_SECONDS` | No | `60` | Clock skew tolerance for `iat`/`exp` validation |
| `HF_CAEP_REPLAY_ENABLED` | No | `true` | Enable replay protection keyed by `jti` |
| `HF_CAEP_REPLAY_TTL_SECONDS` | No | `600` | Replay cache TTL in seconds |
| `HF_CAEP_ENFORCE_ACCOUNT_DISABLED` | No | `false` | Let an analyst's **Lock the account** response (RISC `account-disabled`) disable the Keycloak user and end its sessions |
| `HF_CAEP_ENFORCE_CREDENTIAL_COMPROMISE` | No | `false` | Let an analyst's **Force a new password** response (RISC `credential-compromise`) require `UPDATE_PASSWORD` at the next login and end the sessions |

The two `ENFORCE` switches are **off by default**: an event that changes an account is acted on only when you
enable it. They can also be set as realm attributes (`hf.caep.enforce.accountDisabled`,
`hf.caep.enforce.credentialCompromise`). Ending sessions (CAEP `session-revoked`) follows the existing
`hf.caep.enforce.sessionRevoked` setting. A SET the connector does not act on is answered with
`processing: ignored` and the reason, so Humifortis shows the analyst that nothing was done.

### Example Configuration

```bash
# Required
export HUMIFORTIS_API_KEY=humi_kc_prod_a1b2c3d4e5f6...

# Optional
export HUMIFORTIS_API_URL=https://api.humifortis.educosmic.tech
export HUMIFORTIS_TIMEOUT_MS=800

# Optional CAEP/SSF receiver
export HF_CAEP_ENABLED=true
export HF_CAEP_ISSUER=https://humifortis.example/ssf
export HF_CAEP_AUDIENCE=keycloak-realm
export HF_CAEP_JWKS_URI=https://humifortis.example/.well-known/jwks.json
```

### Realm-scoped CAEP settings

The CAEP receiver is realm-scoped. Each realm can override configuration with realm attributes:

- `hf.caep.enabled`
- `hf.caep.issuer`
- `hf.caep.audience`
- `hf.caep.jwksUri`
- `hf.caep.clockSkewSeconds`
- `hf.caep.replay.enabled`
- `hf.caep.replay.ttlSeconds`
- `hf.caep.supported.sessionRevoked`
- `hf.caep.supported.assuranceLevelChange`
- `hf.caep.enforce.sessionRevoked`
- `hf.caep.enforce.stepUp`
- `hf.caep.enforce.stepUpAsReauth`

> Compatibility note: both underscore (`HF_CAEP_JWKS_URI`) and compact (`HF_CAEP_JWKSURI`) env names are accepted.

## 🏗️ Architecture

### Event Flow

```
User Login Attempt
    ↓
Username/Password ✓
    ↓
Keycloak Event System
    ↓
Humifortis Event Listener (SPI)
    ↓
POST /v1/events
X-API-Key: connector-key
    ↓
Humifortis SaaS
 ├─ Process event
 ├─ Update risk score
 ├─ Apply policies
 └─ Correlate with other systems
```

### RBA Decision Flow

```
User Login Attempt
    ↓
Username/Password ✓
    ↓
Humifortis RBA Authenticator (SPI)
    ↓
GET /v1/risk/{entity_id}/decision
X-API-Key: connector-key
    ↓
Humifortis SaaS responds:
{
  "action": "BLOCK",
  "reason": "High risk score",
  "metadata": {...}
}
    ↓
Connector enforces (no local logic!)
```

## 🔍 Features

### Event Monitoring

The connector automatically captures and sends these security events to Humifortis SaaS:

- ✅ Login success/failure
- ✅ Logout
- ✅ User registration
- ✅ Password updates/resets
- ✅ Email updates/verification
- ✅ Token operations (refresh, revoke, introspect)
- ✅ Service account (client_credentials) logins
- ✅ MFA (TOTP) changes
- ✅ Account deletion
- ✅ Admin operations

### Service accounts (client_credentials)

A client that authenticates with its own credentials (Keycloak "Service accounts enabled",
`client_credentials` grant) is a service account, not a person. Its logins
(`CLIENT_LOGIN` / `CLIENT_LOGIN_ERROR`) are sent as `auth_login_success` / `auth_login_failed`
events of a `service_account` entity, `service_account:keycloak:<realm>:<clientId>`. They feed
detection; with the risk stage enabled (below) each token request is also decided before the token
is issued.

The operator declares what is normal for the client as **client attributes** (Admin console,
Clients, the client, Advanced, Attributes — or the REST API / realm import):

| Client attribute | Meaning | Detection it enables |
|---|---|---|
| `humifortis.source_allowlist` | Comma-separated IPs or CIDRs the client may call from | `SERVICE_ACCOUNT_SOURCE_OUTSIDE_ALLOWLIST` |
| `humifortis.baseline_scopes` | Scopes the client is known to use (space or comma separated) | `SERVICE_ACCOUNT_SCOPE_ESCALATION` |
| `humifortis.expected_window_start_hour_utc`, `humifortis.expected_window_end_hour_utc` | Normal UTC hours of activity, 0-23 (may wrap midnight) | `SERVICE_ACCOUNT_TEMPORAL_ANOMALY` |
| `humifortis.rotation_max_age_days` | Rotation policy of the secret | `CLIENT_CREDENTIAL_STALE` |
| `client.secret.creation.time` | Set by Keycloak when the secret is created or rotated (not edited by hand) | `CLIENT_CREDENTIAL_STALE` |
| `humifortis.owner` | Who owns the client (a team or an e-mail, free text) | shown on the entity page and the alert; never scored |

**Admin events.** An Admin API call made with a service account's token is attributed to the service account (the
client), never to a `user` for Keycloak's internal service-account user. An admin event that changes a service account
(role mappings on its user, client secret regeneration, client changes) also carries `admin.change`
(`privilege_granted`, `privilege_revoked`, `credential_rotated`, `client_config_changed`, `client_deleted`),
`admin.actor_type`, `admin.target_type` / `admin.target_id`, `admin.self_change` and — when the realm records
representations (`adminEventsDetailsEnabled`) — `admin.privileged_role`. These lookups only read the Keycloak model
and fail open: if one fails the event is sent as before.

Each request is judged against the declaration and sent as `service_account.source_allowlist_match`,
`service_account.requested_scopes`, `service_account.historical_scopes`,
`service_account.expected_window_*_hour_utc`, `service_account.credential_age_days` and
`service_account.rotation_max_age_days`. An expectation that is not declared (or not valid) is
not sent: the detector reports its input as unavailable instead of judging against a guess.

### Service accounts: risk stage

The connector ships a client-policy executor, `humifortis-service-account-risk`. Once a realm enables it, every
`client_credentials` token request is sent to Humifortis (`auth_credential_verified`, with the context above) after
Keycloak has checked the client's credentials and **before** the token is issued. The answer is applied as for a
person's login:

| Decision | Token request |
|---|---|
| `DENY` (CRITICAL), mode `enforce` | refused: HTTP 400 `{"error":"access_denied","error_description":"humifortis_risk"}` |
| `DISABLE_CLIENT` (HIGH, or with `DENY` at CRITICAL), mode `enforce`, client with `humifortis.allow_disable=true` | the client is disabled (attributes `humifortis.disabled_at`, `humifortis.disabled_by`), then the request refused as above |
| `DENY` in `shadow` / `dry_run` | issued; the report says it would have been denied |
| anything else (`ALLOW`, `NOTIFY_SOC`, `DISABLE_CLIENT` for a client that does not allow it: advisory) | issued |
| no answer within the budget | issued (fail-open), unless the client sets `humifortis.fallback=deny` |

Every decision is reported (`decision_enforced` or `decision_fallback_applied`). The request's `CLIENT_LOGIN` is
sent as before, in the same flow, and is not decided a second time. A refusal does not produce a failed client login:
it is not a guessed secret.

**Enable it in a realm** — one client profile holding the executor and one client policy applying it to every client
(clients without "Service accounts enabled" are ignored). In a realm import:

```json
"clientProfiles": { "profiles": [ {
  "name": "humifortis-service-account",
  "executors": [ { "executor": "humifortis-service-account-risk", "configuration": {} } ]
} ] },
"clientPolicies": { "policies": [ {
  "name": "humifortis-service-account", "enabled": true,
  "conditions": [ { "condition": "any-client", "configuration": {} } ],
  "profiles": [ "humifortis-service-account" ]
} ] }
```

or in the Admin console: Realm settings, Client policies, Profiles (add the profile and its executor), then Policies
(add the policy with the *Any client* condition and the profile). With `kcadm.sh`, `update
realms/<realm>/client-policies/profiles -f profiles.json` and `update realms/<realm>/client-policies/policies -f
policies.json` (both replace the realm's lists: include the profiles and policies you already have).

| Setting | Default | Meaning |
|---|---|---|
| `HUMIFORTIS_SA_EVALUATE_BUDGET_MS` (env) | `500` | Longest a token request waits for a decision, retries included (ms) |
| `humifortis.enforcement` (client attribute) | — | `off` exempts the client: never evaluated, never refused (its logins still feed detection) |
| `humifortis.fallback` (client attribute) | `allow` | `deny` refuses the token when Humifortis cannot answer |
| `humifortis.allow_disable` (client attribute) | — | `true` lets a decision, or an analyst from the alert, disable the client |

**Disabled clients.** A disabled client is refused by Keycloak itself until an operator re-enables it (Admin console,
Clients, the client, *Enabled*), after clearing its risk in Humifortis — otherwise the next request is decided again on
the same risk. Tokens already issued stay valid until they expire. A client already disabled is not touched, and an
exempt client (`humifortis.enforcement=off`) is never disabled.

**Analyst response.** The alert page of a service account offers *Disable the client*: Humifortis sends a RISC
`account-disabled` security event with the subject `service_account:keycloak:<realm id>:<client id>` over the CAEP
stream, and the receiver disables the client under the same `humifortis.allow_disable` opt-in (the realm switch
`hf.caep.enforce.accountDisabled` is about people's accounts). A client that does not allow it is answered
`processing: ignored` with the reason, and the alert shows that nothing was done.

Keycloak marks the client-policy executor SPI as internal (warning `KC-SERVICES0047` at boot); the stage is tested on
each supported Keycloak version. When building from source, use `mvn clean package`: a stale service-provider file
left in `target/` stops Keycloak from booting.

### Risk-Based Authentication

The RBA authenticator queries Humifortis SaaS for every login and enforces decisions:

| Action | Risk Score | Behavior |
|--------|-----------|----------|
| `ALLOW` | 0-59 | Grant access immediately |
| `CHALLENGE_MFA` | 60-79 | Require additional authentication (OTP/WebAuthn) |
| `BLOCK` | 80-100 | Deny access, show error message |

## 📊 Benefits of Centralized Approach

### Cross-System Correlation

**Example Timeline for john.doe@example.com:**

```
12:00 - Keycloak: Failed login attempt
12:02 - Keycloak: Failed login attempt
12:03 - Okta: Password reset request
12:05 - Custom App: Suspicious API call
12:07 - Keycloak: Login attempt from new IP

→ Humifortis SaaS:
  - Correlates ALL events
  - Risk score: 89 (started at 10)
  - Decision: BLOCK next Keycloak login
  - Alert sent to security team
```

### Policy Evolution Without Redeployment

```
Day 1:  Block at risk 80
Day 30: Adjust to 75 (too many blocks)
Day 60: Add rule for admin users
Day 90: Adjust MFA threshold to 65

✅ All changes made in SaaS GUI
✅ Applied instantly to ALL connectors
✅ No Keycloak restarts
✅ No code deployments
```

### Single Pane of Glass

Instead of checking 19+ dashboards across different systems, security teams get:

- ✅ Unified view of all authentication events
- ✅ Unified risk scores across systems
- ✅ Unified policies
- ✅ Unified alerts
- ✅ Unified audit trail

## 🛠️ Building from Source

### Prerequisites

- Java 17 or later
- Maven 3.8+

### Build

```bash
git clone https://github.com/humifortis/keycloak-connector.git
cd humifortis-keycloak-connector
mvn clean package
```

The JAR file will be created at: `target/humifortis-keycloak-connector.jar`

## 🔧 Development

### Project Structure

```
humifortis-keycloak-connector/
├── src/main/java/tech/humifortis/keycloak/
│   ├── listener/
│   │   ├── HumifortisEventListener.java
│   │   └── HumifortisEventListenerFactory.java
│   ├── auth/
│   │   ├── HumifortisDeviceCollectorAuthenticator.java  ← device step (after the password)
│   │   ├── DeviceSignals.java                       ← reads/validates device signals (all paths)
│   │   ├── HumifortisRiskAuthenticator.java         ← asks Humifortis for the decision
│   │   ├── HumifortisRiskEvaluator.java
│   │   ├── HumifortisStepUpRouter.java / HumifortisHighCondition.java / StepUpActions.java
│   │   └── *Factory.java
│   ├── client/
│   │   ├── SaasClient.java
│   │   ├── SaasConfig.java
│   │   └── SaasException.java
│   ├── mapper/
│   │   └── EventMapper.java
│   └── model/
│       ├── RiskDecision.java
│       └── HumifortisEvent.java
├── src/main/resources/theme-resources/        ← served to EVERY login theme
│   ├── resources/js/humifortis-device.bundle.js ← device collector script (built from device-collector-ui/)
│   └── templates/*.ftl
├── device-collector-ui/                       ← source of the collector script (npm run build)
└── pom.xml
```

### Running Tests

```bash
mvn test
```

## 📖 API Reference

### Event Ingestion

**Endpoint:** `POST /v1/events`

**Headers:**
- `Content-Type: application/json`
- `X-API-Key: {your-api-key}`
- `X-Connector-Type: keycloak`
- `X-Connector-Version: 1.0.0`

**Request Body:**
```json
{
  "event": {
    "entity_id": "user:keycloak:prod:john.doe@example.com",
    "entity_type": "user",
    "timestamp": "2023-12-19T12:13:54.567Z",
    "event_type": "auth_login_failed",
    "source": "keycloak",
    "metadata": {
      "realm": "production",
      "client_id": "web-app",
      "ip": "203.0.113.45",
      "error": "invalid_user_credentials"
    }
  }
}
```

### Risk Decision Query

**Endpoint:** `GET /v1/risk/{entity_id}/decision`

**Headers:**
- `X-API-Key: {your-api-key}`

**Response:**
```json
{
  "entity_id": "user:keycloak:prod:john.doe@example.com",
  "action": "BLOCK",
  "reason": "Risk score exceeds blocking threshold",
  "message_to_user": "Your account has been temporarily locked.",
  "metadata": {
    "risk_score": 89,
    "risk_level": "HIGH",
    "triggered_rules": ["Failed Login Spike"]
  },
  "ttl_seconds": 60,
  "timestamp": "2023-12-19T12:14:00.123Z"
}
```

## 🐛 Troubleshooting

### Connector Not Appearing in Keycloak

1. Check that the JAR is in `/opt/keycloak/providers/`
2. Ensure you ran `/opt/keycloak/bin/kc.sh build`
3. Check Keycloak logs: `/opt/keycloak/data/log/keycloak.log`

### Events Not Appearing in SaaS Dashboard

1. Verify `HUMIFORTIS_API_KEY` is set correctly
2. Check Keycloak logs for connection errors
3. Test connectivity: `curl -H "X-API-Key: $HUMIFORTIS_API_KEY" https://api.humifortis.educosmic.tech/v1/health`
4. Ensure the event listener is enabled in Realm Settings

### RBA Not Working

1. Verify the authenticator is added to the Browser flow
2. Check that it's placed **after** "Username Password Form"
3. Ensure the requirement is set to **REQUIRED**
4. Check logs for decision query errors

## 📝 License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## 🔗 Links

- **Repository:** [https://github.com/humifortis-keycloak-connector](https://github.com/humifortis-keycloak-connector)
- **SaaS Console:** [https://humifortis.educosmic.tech](https://humifortis.educosmic.tech)
- **Documentation:** [https://humifortis.educosmic.tech](https://humifortis.educosmic.tech)
- **Support:** humifortis@tsognong.me

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For issues, questions, or feature requests:
- Email: humifortis@tsognong.me
- GitHub Issues: [https://github.com/humifortis-keycloak-connector/issues](https://github.com/humifortis-keycloak-connector/issues)
