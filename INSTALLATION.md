# Installation Guide

This guide provides detailed instructions for installing and configuring the Humifortis Keycloak Connector.

## Prerequisites

- Keycloak 22.x, 23.x, or 24.x
- Java 17 or later
- Access to Keycloak server filesystem
- Humifortis SaaS account

## Step 1: Register Connector in Humifortis SaaS

1. Navigate to [https://humifortis.educosmic.tech](https://humifortis.educosmic.tech)
2. Login with your credentials
3. Go to **Connectors** → **Add Connector**
4. Fill in the connector details:
   - **Connector Name:** Production Keycloak (or your preferred name)
   - **Connector Type:** Keycloak
   - **Environment:** Production (or Staging/Development)
   - **Tags:** (optional) prod, eu-west-1, auth, etc.
5. Click **Create Connector**
6. **Copy the generated API key** - you'll need this in Step 2

Example API key format: `humi_kc_prod_a1b2c3d4e5f6g7h8i9j0`

## Step 2: Download and Install Connector

### Option A: Download Pre-built JAR

```bash
# Download the latest release
wget https://github.com/humifortis/keycloak-connector/releases/latest/download/humifortis-keycloak-connector.jar

# Copy to Keycloak providers directory
sudo cp humifortis-keycloak-connector.jar /opt/keycloak/providers/
```

### Option B: Build from Source

```bash
# Clone the repository
git clone https://github.com/humifortis/keycloak-connector.git
cd humifortis-keycloak-connector

# Build with Maven
mvn clean package

# Copy to Keycloak providers directory
sudo cp target/humifortis-keycloak-connector.jar /opt/keycloak/providers/
```

## Step 3: Configure Environment Variables

Set the required environment variables. The method depends on how you run Keycloak:

### For Systemd Service

Edit the systemd service file:

```bash
sudo nano /etc/systemd/system/keycloak.service
```

Add these lines in the `[Service]` section:

```ini
[Service]
Environment="HUMIFORTIS_API_URL=https://api.humifortis.educosmic.tech"
Environment="HUMIFORTIS_API_KEY=humi_kc_prod_a1b2c3d4e5f6..."
Environment="HUMIFORTIS_TIMEOUT_MS=5000"
Environment="HUMIFORTIS_FALLBACK_ALLOW=true"
```

Reload systemd:

```bash
sudo systemctl daemon-reload
```

### For Docker/Podman

Add environment variables to your docker-compose.yml:

```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    environment:
      - HUMIFORTIS_API_URL=https://api.humifortis.educosmic.tech
      - HUMIFORTIS_API_KEY=humi_kc_prod_a1b2c3d4e5f6...
      - HUMIFORTIS_TIMEOUT_MS=5000
      - HUMIFORTIS_FALLBACK_ALLOW=true
    volumes:
      - ./humifortis-keycloak-connector.jar:/opt/keycloak/providers/humifortis-keycloak-connector.jar
```

Or via command line:

```bash
docker run -e HUMIFORTIS_API_KEY=humi_kc_prod_a1b2c3d4e5f6... \
  -e HUMIFORTIS_API_URL=https://api.humifortis.educosmic.tech \
  -v ./humifortis-keycloak-connector.jar:/opt/keycloak/providers/humifortis-keycloak-connector.jar \
  quay.io/keycloak/keycloak:23.0 start
```

### For Kubernetes

Create a ConfigMap or Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: humifortis-config
type: Opaque
stringData:
  HUMIFORTIS_API_KEY: humi_kc_prod_a1b2c3d4e5f6...
  HUMIFORTIS_API_URL: https://api.humifortis.educosmic.tech
```

Reference in your deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: keycloak
spec:
  template:
    spec:
      containers:
      - name: keycloak
        image: quay.io/keycloak/keycloak:23.0
        envFrom:
        - secretRef:
            name: humifortis-config
```

### For Manual Start Script

Add to your start script or profile:

```bash
export HUMIFORTIS_API_URL=https://api.humifortis.educosmic.tech
export HUMIFORTIS_API_KEY=humi_kc_prod_a1b2c3d4e5f6...
export HUMIFORTIS_TIMEOUT_MS=5000
export HUMIFORTIS_FALLBACK_ALLOW=true
```

## Step 4: Build and Restart Keycloak

### Standard Installation

```bash
# Build Keycloak with the new provider
/opt/keycloak/bin/kc.sh build

# Start Keycloak
/opt/keycloak/bin/kc.sh start
```

### With Systemd

```bash
sudo systemctl restart keycloak
```

### With Docker

```bash
docker-compose down
docker-compose up -d
```

## Step 5: Enable Event Listener

1. Login to Keycloak Admin Console
2. Select your realm (or create a new one)
3. Navigate to: **Realm Settings** → **Events** tab
4. Scroll to **Event Listeners**
5. Click the dropdown and select: **humifortis-event-listener**
6. Click **Save**

You should now see "humifortis-event-listener" in the enabled listeners list.

## Step 6: Configure Authentication Flow

### Add the Humifortis steps to the Browser flow

1. Navigate to: **Authentication** → **Flows** tab
2. Duplicate the **Browser** flow (e.g. `humifortis-browser`) and open its **Forms** sub-flow
3. After **Username Password Form**, add these two steps, both **REQUIRED**, in this order:
   - **Humifortis Device Collector** — gathers the browser's device signals
   - **Humifortis Risk Authenticator** — asks Humifortis for the decision
4. Bind the new flow as the realm's **Browser flow** (Action → Bind flow)

Your flow should look like this:

```
humifortis-browser
├── Cookie (ALTERNATIVE)
├── Kerberos (DISABLED)
├── Identity Provider Redirector (ALTERNATIVE)
└── Forms (ALTERNATIVE)
    ├── Username Password Form (REQUIRED)
    ├── Humifortis Device Collector (REQUIRED)      ← new
    ├── Humifortis Risk Authenticator (REQUIRED)    ← new
    └── Browser - Conditional OTP (CONDITIONAL)
```

That is all device collection needs: the collector script ships inside the connector jar and
works with **any** login theme. After the password, the user sees a short page (well under a
second) while the device signals are gathered.

### Recommended: collect the device on the login page itself (one line)

Add this line to your login theme's `theme.properties`
(`themes/<your-theme>/login/theme.properties`):

```properties
scripts=js/humifortis-device.bundle.js
```

If the file already has a `scripts=` line, append the entry to it, separated by a space. With it:

- the device signals are sent with the username/password form, so **failed logins carry the
  device too** — needed to detect one device trying several accounts (credential stuffing);
- the short page after the password disappears;
- nothing else changes: the flow stays the same, and if the script cannot run (JavaScript
  disabled or blocked) the login proceeds and the Device Collector step collects as before.

The script never blocks a login: if it has not finished when the user submits, it waits at most
1.5 s, then submits anyway. The signals are bound to the login session (anti-replay) and
checked by the connector.

## Step 7: Test the Installation

### Test Event Listener

1. Open an incognito/private browser window
2. Navigate to your Keycloak login page
3. Attempt a login (success or failure)
4. Go to the Humifortis SaaS dashboard
5. Navigate to **Events** or **Dashboard**
6. Verify that the login event appears

### Test RBA Authenticator

1. In Humifortis SaaS, create a test policy:
   - Go to **Policies** → **Risk-Based Authentication**
   - Set a low threshold to trigger MFA: Risk 30-100 → CHALLENGE_MFA
2. Attempt a login in Keycloak
3. Verify the RBA check occurs (check Keycloak logs if needed)

## Step 8: Verify Installation

### Check Keycloak Logs

```bash
# View recent logs
tail -f /opt/keycloak/data/log/keycloak.log

# Look for these messages:
# [HumifortisEventListener] Humifortis Event Listener initialized successfully
# [HumifortisRiskAuthenticator] ...
```

### Check SaaS Dashboard

1. Login to Humifortis SaaS
2. Go to **Connectors**
3. Find your Keycloak connector
4. Verify:
   - ✓ Status is "Healthy"
   - ✓ Last heartbeat is recent
   - ✓ Events are being received

## Troubleshooting

### Connector Not Showing Up

**Problem:** The connector doesn't appear in Keycloak admin console

**Solution:**
1. Verify JAR is in `/opt/keycloak/providers/`
2. Check file permissions: `sudo chmod 644 /opt/keycloak/providers/humifortis-keycloak-connector.jar`
3. Rebuild: `/opt/keycloak/bin/kc.sh build`
4. Check logs for errors during startup

### API Key Errors

**Problem:** Logs show "Required environment variable not set: HUMIFORTIS_API_KEY"

**Solution:**
1. Verify environment variable is set: `echo $HUMIFORTIS_API_KEY`
2. Ensure it's available to the Keycloak process
3. For systemd, verify the Environment lines in the service file
4. Restart Keycloak after setting variables

### Connection Errors

**Problem:** Logs show "Failed to send event to Humifortis SaaS"

**Solution:**
1. Test connectivity: `curl -H "X-API-Key: $HUMIFORTIS_API_KEY" https://api.humifortis.educosmic.tech/v1/health`
2. Check firewall rules allow outbound HTTPS
3. Verify API key is correct
4. Check SaaS status page

### Events Not Appearing

**Problem:** Events aren't showing in SaaS dashboard

**Solution:**
1. Verify event listener is enabled in Realm Settings
2. Check that monitored events are being triggered (e.g., LOGIN)
3. Review Keycloak logs for event sending errors
4. Ensure API key has correct permissions in SaaS

### RBA Not Enforcing

**Problem:** Logins succeed even with high risk scores

**Solution:**
1. Verify RBA authenticator is in the Browser flow
2. Check it's placed **after** Username Password Form
3. Ensure Requirement is set to **REQUIRED** not DISABLED
4. Check logs for decision query failures
5. Verify policies are configured in SaaS

## Configuration Reference

### Environment Variables

Zero configuration beyond the API key; everything else has a safe default.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HUMIFORTIS_API_URL` | No | `https://api.humifortis.educosmic.tech` | API endpoint (https only) |
| `HUMIFORTIS_API_KEY` | **Yes** | - | API key from connector registration. Without it no login is evaluated (the fallback policy applies) and an error is logged once a minute |
| `HUMIFORTIS_TENANT_ID` | No | realm name | Tenant |
| `HUMIFORTIS_TIMEOUT_MS` | No | `800` | Timeout of ONE API attempt |
| `HUMIFORTIS_EVALUATE_BUDGET_MS` | No | `1500` | Longest a login waits for a decision, retries included |
| `HUMIFORTIS_FALLBACK` | No | (tenant policy) | `allow` \| `step_up` \| `deny` for logins Humifortis cannot answer. Overrides the tenant's policy — an operator's emergency switch |
| `HUMIFORTIS_EVENT_QUEUE_SIZE` | No | `10000` | Events buffered while the API is unreachable |
| `HUMIFORTIS_FALLBACK_ALLOW` | No | - | **Deprecated.** `false` = `HUMIFORTIS_FALLBACK=deny` |

### Resilience: what happens when Humifortis is slow or down

- **Retries.** A failed call (connection error, timeout, HTTP 429/502/503/504) is retried with
  jittered exponential backoff — never beyond `HUMIFORTIS_EVALUATE_BUDGET_MS` for a login. A
  4xx is never retried (a bad key will not get better).
- **Circuit breaker.** After 5 failed calls in a row the connector stops calling for 10 s (then
  20 s, 40 s… up to 2 min), letting one probe through to detect recovery. Logins do not each
  wait out a timeout during an outage.
- **Events are not lost.** Keycloak events wait in a bounded in-memory queue and are delivered
  in order once the API answers again, each exactly once (stable `event_id`). Events older than
  15 minutes are dropped; a full queue drops admin events before login events.
- **Fallback policy.** A login that gets no decision follows your tenant's fallback policy,
  configured in Humifortis (*Decision policy → Enforcement*) and cached by the connector from
  every decision, so it applies during the outage itself. Built-in default (before the first
  decision): ordinary users are allowed, privileged users must pass a second factor (denied if
  they have none). Every such login is reported to Humifortis afterwards
  (`auth_decision_fallback`), and a burst of them raises a SOC alert.

### Reverse proxy and client IP

Every network rule (new network, Tor, impossible travel, threat intelligence) uses the client IP
**as Keycloak resolved it**. Behind a reverse proxy, Keycloak must believe proxy headers from
that proxy **only** — otherwise any client chooses its own IP with an `X-Forwarded-For` header:

```bash
kc.sh start --proxy-headers=xforwarded --proxy-trusted-addresses=10.0.0.5,10.0.0.6
# or: KC_PROXY_HEADERS=xforwarded  KC_PROXY_TRUSTED_ADDRESSES=10.0.0.0/24
```

The edge proxy must **replace** the header with the address it saw, never append to the
client's own:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;   # not $proxy_add_x_forwarded_for on the first hop
```

The connector reports how the IP was resolved with every event; Humifortis raises a HIGH alert
(*Client IP can be forged*) when proxy headers are enabled without trusted addresses.

### Realm attributes (optional)

Set in *Realm settings → General → Unmanaged attributes* (or the admin API):

| Attribute | Example | Meaning |
|-----------|---------|---------|
| `hf.privileged.roles` | `finance-admin, my-app:admin` | Roles that make a user privileged, in addition to Keycloak's administrator roles. Client roles are `clientId:role` |
| `hf.privileged.groups` | `/it/admins, /finance` | Group paths whose members (and subgroups) are privileged |
| `hf.account.createdAttributes` | `createTimestamp, whenCreated` | User attributes holding the creation time of federated (LDAP / AD) accounts |

Roles are **effective** roles: direct, inherited from groups, composites expanded — an
administrator through a group is seen as one. Groups are sent as paths. Both lists are bounded
(100 entries, 4 KiB).

### WebAuthn (passkeys) as a step-up

When a decision requires a phishing-resistant factor (`REQUIRE_WEBAUTHN`, e.g. a tenant access
policy), the step-up router runs Keycloak's own WebAuthn ceremony for users with a passkey or
security key, and falls back to an email code for users without one. No flow change is needed;
enable *Webauthn Register* in *Authentication → Required actions* to let users enroll.

### Monitored Events

The connector monitors these Keycloak events:

- LOGIN, LOGIN_ERROR
- LOGOUT
- REGISTER
- UPDATE_PASSWORD, RESET_PASSWORD, RESET_PASSWORD_ERROR
- UPDATE_EMAIL
- UPDATE_TOTP, REMOVE_TOTP
- CODE_TO_TOKEN_ERROR, REFRESH_TOKEN_ERROR

## Next Steps

After installation:

1. **Configure Policies** in Humifortis SaaS dashboard
2. **Set thresholds** for ALLOW/CHALLENGE_MFA/BLOCK actions
3. **Create custom rules** for specific scenarios
4. **Monitor the dashboard** for security events
5. **Adjust policies** based on real-world usage

## Support

For assistance:
- Email: support@humifortis.tech
- Documentation: https://docs.humifortis.tech/connectors/keycloak
- GitHub Issues: https://github.com/humifortis/keycloak-connector/issues
