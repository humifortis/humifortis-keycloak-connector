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
   - Select: "Humifortis Risk-Based Authentication"
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
| `HUMIFORTIS_TIMEOUT_MS` | No | `5000` | HTTP request timeout in milliseconds |
| `HUMIFORTIS_FALLBACK_ALLOW` | No | `true` | Allow/block access if SaaS is unreachable |

### Example Configuration

```bash
# Required
export HUMIFORTIS_API_KEY=humi_kc_prod_a1b2c3d4e5f6...

# Optional
export HUMIFORTIS_API_URL=https://api.humifortis.educosmic.tech
export HUMIFORTIS_TIMEOUT_MS=5000
export HUMIFORTIS_FALLBACK_ALLOW=true
```

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
- ✅ MFA (TOTP) changes
- ✅ Account deletion
- ✅ Admin operations

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
│   │   ├── HumifortisRBAAuthenticator.java
│   │   └── HumifortisRBAAuthenticatorFactory.java
│   ├── client/
│   │   ├── SaasClient.java
│   │   ├── SaasConfig.java
│   │   └── SaasException.java
│   ├── mapper/
│   │   └── EventMapper.java
│   └── model/
│       ├── RiskDecision.java
│       └── HumifortisEvent.java
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

- **Repository:** [https://github.com/humifortis/keycloak-connector](https://github.com/humifortis/keycloak-connector)
- **SaaS Console:** [https://humifortis.educosmic.tech](https://humifortis.educosmic.tech)
- **Documentation:** [https://docs.humifortis.tech/connectors/keycloak](https://docs.humifortis.tech/connectors/keycloak)
- **Support:** humifortis@tsognong.me

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For issues, questions, or feature requests:
- Email: humifortis@tsognong.me
- GitHub Issues: [https://github.com/humifortis/keycloak-connector/issues](https://github.com/humifortis/keycloak-connector/issues)
