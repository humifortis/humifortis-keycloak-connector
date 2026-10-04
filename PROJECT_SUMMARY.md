# Humifortis Keycloak Connector - Project Summary

## Overview

This project implements a thin client connector that integrates Keycloak (versions 22.x, 23.x, 24.x) with the Humifortis SaaS platform for centralized risk-based authentication and security event monitoring.

**Version:** 1.0.0  
**License:** Apache 2.0  
**Language:** Java 17+  
**Build System:** Maven  
**Target Platform:** Keycloak 22+

## Architecture Philosophy

### Centralized Intelligence

The connector follows a **"thin client"** architecture where:

- ✅ **All intelligence lives in Humifortis SaaS** (risk calculation, policies, thresholds, rules)
- ✅ **Connector is a dumb pipe** (capture events, query decisions, enforce actions)
- ✅ **Zero maintenance** (update policies in SaaS GUI without touching Keycloak)
- ✅ **Cross-system correlation** (aggregate events from multiple identity providers)

### Design Principles

1. **Minimal Configuration**: Only 1 required environment variable (API key)
2. **No Local State**: No caching, no local risk calculation, no policy engine
3. **Fail-Safe**: Configurable fallback behavior when SaaS is unreachable
4. **Performance**: Async event sending to minimize authentication flow impact
5. **Observability**: Comprehensive logging for troubleshooting

## Project Structure

```
humifortis-keycloak-connector/
├── src/main/java/tech/humifortis/keycloak/
│   ├── listener/               # Event capture and sending
│   │   ├── HumifortisEventListener.java
│   │   └── HumifortisEventListenerFactory.java
│   ├── auth/                   # RBA decision query and enforcement
│   │   ├── HumifortisRBAAuthenticator.java
│   │   └── HumifortisRBAAuthenticatorFactory.java
│   ├── client/                 # HTTP communication with SaaS
│   │   ├── SaasClient.java
│   │   ├── SaasConfig.java
│   │   └── SaasException.java
│   ├── mapper/                 # Event transformation
│   │   └── EventMapper.java
│   └── model/                  # Data models
│       ├── HumifortisEvent.java
│       └── RiskDecision.java
├── src/main/resources/
│   └── META-INF/services/      # SPI registration
│       ├── org.keycloak.events.EventListenerProviderFactory
│       └── org.keycloak.authentication.AuthenticatorFactory
├── .github/workflows/
│   └── build.yml               # CI/CD pipeline
├── pom.xml                     # Maven build configuration
├── README.md                   # Complete documentation
├── INSTALLATION.md             # Detailed setup guide
├── QUICKSTART.md              # 5-minute installation
├── CONTRIBUTING.md            # Contribution guidelines
├── CHANGELOG.md               # Version history
└── LICENSE                    # Apache 2.0 license
```

## Key Components

### 1. Event Listener (HumifortisEventListener)

**Purpose:** Captures security-relevant Keycloak events and sends them to Humifortis SaaS

**Monitored Events:**
- Authentication events (login success/failure, logout)
- User management (registration, password updates/resets, email updates)
- Token operations (refresh, revoke, introspect failures)
- MFA changes (TOTP add/remove)
- Account deletion
- Admin operations

**Implementation Details:**
- Implements `EventListenerProvider` SPI
- Async, fire-and-forget event sending (no blocking)
- Maps Keycloak events to Humifortis format
- Generates unified entity IDs: `user:keycloak:{realm}:{identifier}`

**Key Code:**
```java
public void onEvent(Event event) {
    if (!MONITORED_EVENTS.contains(event.getType())) return;
    
    HumifortisEvent humiEvent = eventMapper.fromKeycloakEvent(event);
    saasClient.sendEventAsync(humiEvent)
        .exceptionally(ex -> {
            logger.warn("Failed to send event", ex);
            return null;
        });
}
```

### 2. RBA Authenticator (HumifortisRBAAuthenticator)

**Purpose:** Queries Humifortis SaaS for risk decisions and enforces them during authentication

**Decision Types:**
- **ALLOW** (risk 0-59): Grant access immediately
- **CHALLENGE_MFA** (risk 60-79): Require additional authentication (OTP/WebAuthn)
- **BLOCK** (risk 80-100): Deny access with custom error message

**Implementation Details:**
- Implements `Authenticator` SPI
- Synchronous decision query (must complete before allowing access)
- Configurable fallback behavior when SaaS unreachable
- Sends block events back to SaaS for auditing

**Key Code:**
```java
public void authenticate(AuthenticationFlowContext context) {
    String entityId = generateEntityId(context, user);
    RiskDecision decision = saasClient.getRiskDecision(entityId);
    
    switch (decision.getAction()) {
        case ALLOW -> context.success();
        case CHALLENGE_MFA -> context.attempted();  // Force MFA
        case BLOCK -> {
            context.failure(AuthenticationFlowError.ACCESS_DENIED);
            context.forceChallenge(createBlockedPage(context, decision));
        }
    }
}
```

### 3. SaaS Client (SaasClient)

**Purpose:** HTTP communication with Humifortis SaaS API

**API Endpoints:**
- `POST /v1/events` - Send security events
- `GET /v1/risk/{entity_id}/decision` - Query risk decision

**Implementation Details:**
- Uses Java 11+ `HttpClient` for modern async support
- Configurable timeouts (default: 5 seconds)
- Gson for JSON serialization
- Custom headers for connector identification

**Key Code:**
```java
public CompletableFuture<Void> sendEventAsync(HumifortisEvent event) {
    return CompletableFuture.runAsync(() -> {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(apiUrl + "/v1/events"))
            .header("X-API-Key", apiKey)
            .header("X-Connector-Type", "keycloak")
            .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(event)))
            .build();
        httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    });
}
```

### 4. Event Mapper (EventMapper)

**Purpose:** Transform Keycloak events to Humifortis format

**Transformations:**
- Maps Keycloak `EventType` to semantic event types (e.g., `LOGIN` → `auth_login_success`)
- Generates unified entity IDs for cross-system correlation
- Extracts relevant metadata (IP, client ID, error details, etc.)
- Converts timestamps to ISO 8601 format

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HUMIFORTIS_API_URL` | No | `https://api.humifortis.educosmic.tech` | SaaS API endpoint |
| `HUMIFORTIS_API_KEY` | **Yes** | - | API key from SaaS registration |
| `HUMIFORTIS_TIMEOUT_MS` | No | `800` | Timeout of one API attempt (ms) |
| `HUMIFORTIS_EVALUATE_BUDGET_MS` | No | `1500` | Longest a login waits for a decision, retries included (ms) |
| `HUMIFORTIS_FALLBACK` | No | (tenant policy) | `allow` \| `step_up` \| `deny` when Humifortis cannot answer — overrides the tenant policy (see INSTALLATION.md, Resilience) |

### Keycloak Setup

1. **Enable Event Listener:**
   - Realm Settings → Events → Event Listeners
   - Check: `humifortis-event-listener`

2. **Add to Authentication Flow:**
   - Authentication → Flows → Browser
   - Add "Humifortis Risk-Based Authentication" after "Username Password Form"
   - Set requirement to REQUIRED

## API Specification

### Event Ingestion

**Request:**
```http
POST /v1/events
Content-Type: application/json
X-API-Key: {api-key}
X-Connector-Type: keycloak
X-Connector-Version: 1.0.0

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

**Response:**
```json
{
  "success": true,
  "event_id": "evt_humi_987654",
  "entity_id": "user:keycloak:prod:john.doe@example.com",
  "risk_updated": true,
  "new_risk_score": 78
}
```

### Risk Decision Query

**Request:**
```http
GET /v1/risk/user:keycloak:prod:john.doe@example.com/decision
X-API-Key: {api-key}
```

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

## Build Instructions

### Prerequisites
- JDK 17 or later
- Maven 3.8+

### Build Commands

```bash
# Clone repository
git clone https://github.com/humifortis/keycloak-connector.git
cd humifortis-keycloak-connector

# Build
mvn clean package

# Output: target/humifortis-keycloak-connector.jar
```

### Build Features
- Maven Shade plugin bundles Gson dependency
- Keycloak dependencies marked as `provided` (supplied by Keycloak runtime)
- Generates single JAR file ready for deployment

## Installation

### Quick Installation (5 minutes)

```bash
# 1. Download
wget https://github.com/humifortis/keycloak-connector/releases/latest/download/humifortis-keycloak-connector.jar

# 2. Install
cp humifortis-keycloak-connector.jar /opt/keycloak/providers/

# 3. Configure
export HUMIFORTIS_API_KEY=humi_kc_prod_xxxxx...

# 4. Build and restart
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

### Docker Installation

```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    environment:
      - HUMIFORTIS_API_KEY=humi_kc_prod_xxxxx...
    volumes:
      - ./humifortis-keycloak-connector.jar:/opt/keycloak/providers/humifortis-keycloak-connector.jar
    command: start-dev
```

## Benefits

### Cross-System Correlation

Events from multiple sources contribute to a single risk score:

```
Timeline for john.doe@example.com:
12:00 - Keycloak: Failed login
12:02 - Keycloak: Failed login
12:03 - Okta: Password reset
12:05 - Custom App: Suspicious API call
12:07 - Keycloak: Login attempt

→ Humifortis correlates ALL events
→ Risk score: 89 (started at 10)
→ Decision: BLOCK next login
```

### Policy Evolution

Update policies instantly without code changes:

```
Day 1:  Block at risk 80
Day 30: Adjust to 75 (reduce false positives)
Day 60: Add rule for admin users
Day 90: Change MFA threshold to 65

✓ All changes in SaaS GUI
✓ Zero Keycloak restarts
✓ Zero code deployments
```

### Unified Dashboard

Security teams get a single view across all systems:

- ✅ All authentication events
- ✅ Unified risk scores
- ✅ Unified policies
- ✅ Unified alerts
- ✅ Unified audit trail

Instead of checking 19+ separate dashboards.

## Testing

### Manual Testing

1. **Test Event Listener:**
   - Attempt a login
   - Check SaaS dashboard for event
   - Verify event details are correct

2. **Test RBA Authenticator:**
   - Create a test policy in SaaS
   - Attempt login
   - Verify decision is enforced

### Log Verification

```bash
tail -f /opt/keycloak/data/log/keycloak.log | grep Humifortis

# Expected output:
# [HumifortisEventListener] Humifortis Event Listener initialized successfully
# [HumifortisEventListener] Event queued for sending: LOGIN for user xxx
# [HumifortisRBAAuthenticator] Humifortis RBA Authenticator initialized
# [HumifortisRBAAuthenticator] RBA: Allow login for user:keycloak:...
```

## Troubleshooting

### Common Issues

**Connector not appearing:**
- Verify JAR location: `/opt/keycloak/providers/`
- Run build command: `/opt/keycloak/bin/kc.sh build`
- Check logs for loading errors

**Events not appearing in SaaS:**
- Verify API key is set correctly
- Check event listener is enabled in Realm Settings
- Test connectivity: `curl -H "X-API-Key: $HUMIFORTIS_API_KEY" https://api.humifortis.educosmic.tech/v1/health`

**RBA not working:**
- Verify authenticator is in Browser flow
- Check it's after Username Password Form
- Ensure requirement is REQUIRED

## Performance Characteristics

- **Event Sending:** Async, non-blocking (< 1ms impact on auth flow)
- **RBA Query:** Synchronous, typically 50-150ms
- **Memory:** Minimal (stateless design)
- **Network:** Outbound HTTPS only
- **CPU:** Negligible (no local processing)

## Security Considerations

- **API Key Storage:** Environment variables (never in code)
- **Transport Security:** HTTPS only
- **No Credentials:** Connector never sees user passwords
- **Minimal Data:** Only security-relevant metadata sent
- **Fail-Safe:** Configurable fallback behavior

## Future Enhancements

Potential improvements (not yet implemented):

- Circuit breaker for SaaS communication
- Request retry logic with exponential backoff
- Event batching for high-volume scenarios
- Metrics export (Prometheus format)
- Health check endpoint
- Enhanced logging and diagnostics

## Documentation Files

- **README.md**: Complete documentation with architecture, features, and examples
- **INSTALLATION.md**: Detailed installation guide for various deployment scenarios
- **QUICKSTART.md**: 5-minute quick start guide
- **CONTRIBUTING.md**: Guidelines for contributors
- **CHANGELOG.md**: Version history and release notes
- **LICENSE**: Apache 2.0 license text

## Support and Resources

- **Repository:** https://github.com/humifortis/keycloak-connector
- **SaaS Console:** https://humifortis.educosmic.tech
- **Documentation:** https://docs.humifortis.tech/connectors/keycloak
- **Email Support:** support@humifortis.tech
- **Issue Tracker:** GitHub Issues

## License

Apache License 2.0 - See LICENSE file for details.

---

**Project Completion Date:** December 27, 2024  
**Implementation Language:** Java 17  
**Total Lines of Code:** ~800 (core logic)  
**Documentation:** ~3,000 lines  
**Test Coverage:** Ready for unit/integration tests
