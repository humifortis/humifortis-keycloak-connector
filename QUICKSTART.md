# Quick Start Guide

Deploy the Humifortis Keycloak Connector in under 5 minutes.

## Prerequisites

- Keycloak 22+ running
- Access to server filesystem
- Humifortis SaaS account

## 3-Step Installation

### 1. Get API Key (1 minute)

```
1. Login to https://humifortis.educosmic.tech
2. Connectors → Add Connector → Keycloak
3. Copy API key: humi_kc_prod_xxxxx...
```

### 2. Install Connector (2 minutes)

```bash
# Download
wget https://github.com/humifortis/keycloak-connector/releases/latest/download/humifortis-keycloak-connector.jar

# Install
cp humifortis-keycloak-connector.jar /opt/keycloak/providers/

# Configure
export HUMIFORTIS_API_KEY=humi_kc_prod_xxxxx...

# Restart
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

### 3. Enable in Keycloak (2 minutes)

**Enable Event Listener:**
```
Realm Settings → Events → Event Listeners
☑️ humifortis-event-listener
Save
```

**Add to Auth Flow:**
```
Authentication → Flows → Browser → Add Step
Select: "Humifortis Risk Authenticator" (after "Humifortis Device Collector" — see INSTALLATION.md, Step 6)
Place after: "Username Password Form"
Requirement: REQUIRED
Save
```

## Test

1. Attempt a login
2. Check Humifortis dashboard for events
3. Done!

## Docker Quick Start

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

## Configuration

Only 1 required variable:

```bash
export HUMIFORTIS_API_KEY=your_api_key_here
```

Optional:
```bash
export HUMIFORTIS_TIMEOUT_MS=5000
export HUMIFORTIS_FALLBACK_ALLOW=true
```

## Verify Installation

```bash
# Check logs
tail -f /opt/keycloak/data/log/keycloak.log | grep Humifortis

# Look for:
# ✓ "Humifortis Event Listener initialized successfully"
# ✓ "Humifortis RBA Authenticator initialized"
```

## Troubleshooting

**Connector not appearing?**
- Verify JAR is in `/opt/keycloak/providers/`
- Run `/opt/keycloak/bin/kc.sh build`
- Check logs for errors

**Events not in dashboard?**
- Verify API key is set: `echo $HUMIFORTIS_API_KEY`
- Check event listener is enabled
- Test connectivity: `curl -H "X-API-Key: $HUMIFORTIS_API_KEY" https://api.humifortis.educosmic.tech/v1/health`

**RBA not working?**
- Verify authenticator is in Browser flow
- Check it's **after** Username Password Form
- Ensure requirement is **REQUIRED**

## Next Steps

Configure policies in SaaS dashboard:
- Set risk thresholds
- Create custom rules
- Monitor events
- Adjust based on usage

## Support

- 📧 support@humifortis.tech
- 📚 https://docs.humifortis.tech/connectors/keycloak
- 🐛 https://github.com/humifortis/keycloak-connector/issues
