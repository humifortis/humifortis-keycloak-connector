# Installation Guide

This guide provides detailed instructions for installing and configuring the Humifortis Keycloak Connector.

## Prerequisites

- Keycloak 26.8.1 (the version this connector is built and tested against)
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
    image: quay.io/keycloak/keycloak:26.8.1
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
  quay.io/keycloak/keycloak:26.8.1 start
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
        image: quay.io/keycloak/keycloak:26.8.1
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
4. Add a sub-flow named `humifortis-mfa-subflow` to **Forms**, requirement **CONDITIONAL**, after the Risk Authenticator, and in it two steps, both **REQUIRED**, in this order:
   - **Humifortis High Condition** — matches when Humifortis asks for a second factor
   - **Humifortis Step-Up Router** — runs the factor: an email code, Keycloak's OTP form (authenticator app) or Keycloak's WebAuthn (passkey)
5. Bind the new flow as the realm's **Browser flow** (Action → Bind flow)

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
    └── humifortis-mfa-subflow (CONDITIONAL)        ← new
        ├── Humifortis High Condition (REQUIRED)
        └── Humifortis Step-Up Router (REQUIRED)
```

**The MFA sub-flow is what challenges.** When Humifortis asks for a step-up the Risk Authenticator lets the flow go on and
this sub-flow runs the factor. Without it the person is signed in with no second factor; the connector then logs an
error (`step-up ... decided but no second factor ran`) and reports the login with `divergence=step_up_not_executed`.
The sub-flow needs no `OTP Form` step: the router runs Keycloak's own OTP form itself, and a user who has no
authenticator app gets the email code. Enable *Webauthn Register* and *Configure OTP* in
**Authentication → Required actions** to let people enroll a passkey or an authenticator app.

**The factor is decided by Humifortis.** The step-up router challenges the `required_factor` of the decision (e-mail code,
text message, authenticator app or passkey); its own `fallback.order` is used only when Humifortis could not be reached, and
as the next choice when the required factor cannot be delivered (the difference is reported). Humifortis chooses from the
factors the connector advertises: enrolled credentials, a verified e-mail, a number with a configured SMS gateway.

**When Humifortis cannot be reached,** the tenant's fallback policy applies (cached from earlier answers). `allow` (the default
for ordinary users) means your own flow runs exactly as if Humifortis were not installed. `step_up` challenges the person
with the factor she already has (passkey, authenticator app), then e-mail or text; `deny` refuses. Each is reported, and a
burst raises a SOC alert.

**Session reuse (optional).** Enable *Humifortis session check* in **Authentication → Required actions** to have a sign-in that
reuses an existing single-sign-on session evaluated. A deny or step-up ends that session and the person signs in again in full;
in `dry_run` / `shadow` it is only reported.

**Text-message codes (optional).** Set `HUMIFORTIS_SMS_GATEWAY_URL` (https, or http with `HUMIFORTIS_ALLOW_INSECURE_HTTP=true`) and
optionally `HUMIFORTIS_SMS_GATEWAY_TOKEN` (bearer) on Keycloak. The connector posts `{"to":"+15145550100","message":"..."}`; any
2xx is a delivery. The number is read from the user attribute `phoneNumber` (change with `HUMIFORTIS_SMS_PHONE_ATTRIBUTE`; declare it
in **Realm settings → User profile**), in E.164. A person without a verified email but with a number is texted; without the URL
the channel does not exist.

That is all device collection needs: the collector script ships inside the connector jar and
works with **any** login theme. After the password, the user sees a short page (well under a
second) while the device signals are gathered.

### Password grant (optional)

A client that sends the username and password itself (the OAuth *password grant*, Keycloak's **Direct grant** flow) never
reaches the Browser flow, so Humifortis does not see it. To evaluate it, open the realm's **Direct grant** flow and add
**Humifortis Direct Grant Risk** (**REQUIRED**) after the password step. A deny, and any decision that asks for a second
factor, then refuses the token with `401 {"error":"access_denied","error_description":"humifortis_risk"}` — no page exists in
this flow to ask for the factor. With no answer from Humifortis the tenant's fallback policy decides (allow unless it says
deny); in `dry_run` and `shadow` nothing is refused. Where a client does not need the password grant, switch *Direct access
grants* off for it instead.

### Refresh tokens (optional)

A refresh-token request goes to the token endpoint, not through the Browser flow. To evaluate it, create a **client profile**
holding the executor **humifortis-token-refresh-risk** and a **client policy** that applies the profile to the clients you
want (*Realm settings → Client policies*). A deny, and any decision that asks for a second factor, then refuses the refresh
(`400 {"error":"invalid_grant","error_description":"humifortis_risk"}`): the client sends the person through the browser
flow again, where the decision is enforced with a page. With no answer from Humifortis the refresh goes on, unless the client
has the attribute `humifortis.fallback=deny`; a client with `humifortis.enforcement=off` is never evaluated; in `dry_run`
and `shadow` nothing is refused. Nothing changes for a realm that does not create the profile and the policy.

### Token exchange (optional)

A client that trades a person's token for another one (RFC 8693 *standard token exchange*) can be evaluated the same way as
a refresh: put the executor **humifortis-token-exchange-risk** in a client profile and apply it with a client policy. A deny,
and any decision that asks for a second factor, refuses the exchange (`access_denied` / `humifortis_risk`). Same fallback
and opt-outs as for refresh tokens. The JWT authorization grant has no Keycloak hook for such a stage: switch it off unless
you need it.

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

## Let your own flow decide (optional): the local decision source

By default Humifortis decides and the connector applies the decision (`server`). With the **local** source your Keycloak
flow decides, using what Humifortis found: the connector asks for the *evaluation context* of each login (risk level, the
rules that fired, a few attributes, the reasons), writes it into the authentication session, and the flow reacts with
Humifortis conditions. Humifortis keeps measuring: it reports what your flow did, so the console can show where your
policy and the platform's agree.

**What stays with Humifortis.** An *explicit deny* (a block rule of the platform or of your own tenant rules, and a
lock of the account) is enforced by the connector before any condition of your flow is looked at: a flow cannot relax it.
The *baseline* deny for the CRITICAL level is a recommendation your flow decides on. To keep it, add the deny step
(the default flow does), or add the tenant rule *Block critical logins* in Humifortis, which makes it explicit.
In `dry_run` and `shadow` nothing is enforced and the conditions never match, with either source.

**Turn it on** (one of the two):

- for a whole Keycloak: `HUMIFORTIS_DECISION_SOURCE=local`;
- for one flow: *Humifortis Risk Authenticator* > Config > *Decision source* = `local` (wins over the variable, so a realm moves one flow at a time).

**The default flow** (it behaves like the `server` source: it honours the platform's step-up and deny) is created by
`scripts/install_local_decision_flow.py` (Python 3.8+, standard library only; add `--bind` to make it the browser flow):

```bash
KC_URL=https://sso.example.com KC_REALM=myrealm KC_ADMIN_USER=admin KC_ADMIN_PASSWORD=... \
  python3 scripts/install_local_decision_flow.py --bind
```

Customise it with Keycloak's flow structure and these conditions (all placed after *Humifortis Risk Authenticator*):

| Condition | Matches when |
|---|---|
| Humifortis high risk (`outcome = step_up` or `deny`) | the platform's decision is a step-up, or a (baseline) deny |
| Humifortis risk level at least | the risk level is at least the one you choose |
| Humifortis rule fired | the named Humifortis rule fired for this login |
| Humifortis attribute equals | an allowlisted attribute equals the value (booleans without case) |

There is no `contains`, no prefix match and no expression: anything richer is written once as a rule in Humifortis, and
the flow tests *rule fired*. Two conditional sub-flows that both match challenge the person once.

Keep **Humifortis decision report** as the last step of the flow: it reports what the flow did. Without it Humifortis
sees the decisions but not what the flow did with them. In the deny sub-flow, put a second one (*Report as* = `deny`)
just before **Deny access**, which ends the flow and so cannot be followed by a report.

Attributes offered to the conditions are those of `HUMIFORTIS_CONTEXT_ATTRIBUTES` (comma-separated; default
`network.is_anonymous, network.is_tor, network.is_vpn, network.is_datacenter, network.country_mismatch,
network.implied_speed_kmh, device.first_seen`). Never add an address, an e-mail or a user agent: the session notes are
kept by the Keycloak server and every other provider of the realm can read them.

**If the context is missing** (an older Humifortis, an unknown context version) the login behaves as `server`: the
platform's decision is enforced, and the connector logs `context_missing`. If your flow runs a Humifortis step-up
condition without the risk authenticator before it, the person is challenged, never let through.

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
4. Check the **MFA sub-flow** (Step 6) is in the Forms flow: without it a step-up decision is not carried out
   (the Keycloak log shows `step-up ... decided but no second factor ran`)
5. Check logs for decision query failures
6. Verify policies are configured in SaaS

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

### Directory federation (LDAP / Active Directory)

Nothing to configure in the connector. With a directory federated under *User federation*, every event and decision says
where the account comes from (`account_source`): `local`, `ldap:<provider name>`, `ad:<provider name>` (the provider's
*Vendor* is Active Directory) or `brokered:<identity provider alias>`. The source is the account's origin, not proof of how
this sign-in's password was checked. Humifortis shows it on the entity list and page, on alerts, in Reporting, and a decision
rule can read it (`identity.account_source`).

What the connector does for federated people:

- **Account age** comes from the directory (`createTimestamp`, `whenCreated`, or `hf.account.createdAttributes`), not from
  the import at the first sign-in: a ten-year-old employee is not a new account. Keycloak's default LDAP mappers already
  include the creation date.
- **A directory that does not answer is not a wrong password.** When Keycloak cannot reach the directory, a person it imported
  before is reported as `directory_unavailable` (with the provider name) instead of a failed sign-in, and Humifortis opens one
  operational alert per directory. A person never imported cannot be told apart and stays a failed sign-in.
- **Privilege from directory groups**: map the directory's groups with a *group-ldap-mapper* and list the privileged group
  paths in `hf.privileged.groups` (for example `/administrators`).

- **A disabled account is not a wrong password.** Keycloak checks the password first and the enabled flag after it, so its
  `user_disabled` error means the right password was used on a disabled account: the connector reports it as
  `auth_account_disabled` (a leaver, or someone holding the credentials), never as a failed sign-in. A wrong password stays a
  failed sign-in, disabled account or not.

Recommended setting: *Cache policy* `NO_CACHE` on the federation, so a change in the directory (a person added to an
administrators group, an attribute) is seen at the person's next sign-in. With Keycloak's default cache, an imported person's
groups are refreshed only when the cache entry expires.

**Active Directory.** Set *Vendor* to Active Directory and *Edit mode* to `WRITABLE`. Keycloak's AD account-control mapper
acts on the domain's answer to a sign-in only in writable mode: an account disabled in the domain becomes Keycloak's
`user_disabled` (reported as above), and a password that must change at next logon gets Keycloak's password-update page.
In read-only mode both are refused as a wrong password, so they count as failed sign-ins and a person whose password expired
can be blocked for retrying it. Changing the password from Keycloak needs LDAPS (AD accepts a new password only over an
encrypted connection). For nested groups (a group inside *Domain Admins*), use a *group-ldap-mapper* with the retrieve strategy
`LOAD_GROUPS_BY_MEMBER_ATTRIBUTE_RECURSIVELY`, its *LDAP Groups DN* on the container that holds the groups (for example
`CN=Users,DC=corp,DC=example`; Keycloak does not search below it), a *Groups path* such as `/corp-ad`, and list
`/corp-ad/Domain Admins` in `hf.privileged.groups`.

### Brokered logins (an external identity provider)

A person who signs in through an identity provider (*Identity providers*: another Keycloak, Entra ID, Okta, Google…)
never sees the realm's password form, so the browser flow's Humifortis steps do not run and **nothing is decided**. Give
each identity provider a *Post login flow* that runs them after the provider returned:

1. *Authentication → Create flow* `humifortis-post-broker` (basic flow), with, in order:
   - *Humifortis Device Collector*: Required;
   - *Humifortis Risk Authenticator*: Required;
   - a sub-flow (Conditional) holding *Humifortis High Condition* (Required) and *Humifortis Step-Up Router* (Required).
2. *Identity providers → (your provider) → Post login flow*: `humifortis-post-broker`.

The decision is then taken for every brokered sign-in, at the same moment as for a password: a step-up asks the factor
Humifortis decided, a deny refuses the sign-in although the provider vouched for the person, and the decision names the
provider (`identity_provider`) and the account source (`brokered:<alias>`). A session later reused by another application is
judged by the session check like any session.

When a provider fails (it does not answer, answers with an error or with something that is not a token), Keycloak shows its
own error page and the person is not signed in. The connector reports it against the integration, not against anyone:
Humifortis raises one alert per provider ("Identity provider `<alias>` fails — sign-ins through it are refused"), and nobody's
risk or failed-password count changes. Keycloak's event carries no cause; it is in Keycloak's server log.

For single logout, the provider must accept the realm's broker endpoint as a post-logout redirect
(`https://<keycloak>/realms/<realm>/broker/<alias>/endpoint/*`); otherwise the provider's logout fails and the realm's
session is not ended.

### SAML applications

A SAML application (a client of protocol *SAML* in the realm; Keycloak is its identity provider) signs its people in
through the realm's browser flow, so Humifortis decides it exactly as it decides an OpenID Connect application: nothing to
configure. A denied person receives **no assertion**; a step-up comes before it. The decision names the protocol
(`auth_method`: `saml`) and the application (`client_id`). A SAML application that reuses a single-sign-on session is
judged by the session check like any other. For single logout, the application must answer Keycloak's logout request with
a logout response: Keycloak ends the session only once every SAML application has answered.

### WebAuthn (passkeys) as a step-up

When a decision requires a phishing-resistant factor (`REQUIRE_WEBAUTHN`, e.g. a tenant access
policy), the step-up router runs Keycloak's own WebAuthn ceremony for users with a passkey or
security key, and falls back to an email code for users without one. No flow change is needed;
enable *Webauthn Register* in *Authentication → Required actions* to let users enroll.

**Kinds of credential.** A security key, a passkey kept in one device and a passkey synced through a cloud account are all
WebAuthn. Keycloak does not keep the flag that tells a synced passkey from a device-bound one, so the connector reads it
from what the browser posts: at the registration (now reported as an enrolment) and at each step-up. Humifortis
remembers the kind of each credential and shows it on the person and in Reporting. Nothing to configure in Keycloak.

A tenant that counts only security keys and device-bound passkeys as phishing-resistant sets, in its Humifortis
configuration, `assurance.phishing_resistant: device_bound` (default `any`). A synced passkey then counts as an app-level
factor: with `assurance.shortfall: best_available` the person is still stepped up with it and the shortfall is recorded;
with `deny` she is refused. When a person holds both kinds, the decision asks for the stronger one, and the step-up refuses
a synced passkey presented in its place ("This passkey cannot be used here"), recorded as a failed step-up.

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

## Which Humifortis call does the connector make

The connector uses the two calls of the Humifortis API for two different jobs. The rule is: **if the answer changes
what you do, it is `POST /evaluate`; if not, it is `POST /events`.**

| You need to... | Call |
|---|---|
| allow, step up or deny a sign-in, a token request or an admin action now | `POST /evaluate` (one event, answers with a decision) |
| tell Humifortis about something that already happened (a logout, an MFA enrolment, a password change, a failed attempt after the fact) | `POST /events` |
| send many events at once, or from a queue | `POST /events` (up to 100 per call) |

Both take the same `event` object. `POST /evaluate` adds the caller's context (the MFA profile and the executors) and
does not take batches. Only `POST /evaluate` returns an action, so a login that must be enforced is never sent to
`POST /events`.
