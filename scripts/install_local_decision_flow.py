#!/usr/bin/env python3
"""Creates the default flow of the LOCAL decision source in a realm (INSTALLATION.md, "Let your own flow decide").

  hf-local-browser
    auth-cookie                                   ALTERNATIVE
    hf-local-browser-forms                        ALTERNATIVE
      Username Password Form                      REQUIRED
      Humifortis Device Collector                 REQUIRED
      Humifortis Risk Authenticator               REQUIRED   (Decision source = local)
      hf-local-browser-deny                       CONDITIONAL   Humifortis high risk (outcome = deny)
                                                                -> Humifortis decision report (deny) -> Deny access
      hf-local-browser-mfa                        CONDITIONAL   Humifortis high risk (outcome = step_up) -> step-up router
      Humifortis decision report                  REQUIRED   (last step)

The flow honours the platform: a step-up is asked when Humifortis asks for one, a deny when the baseline denies. Change it
like any Keycloak flow, with the Humifortis conditions. An explicit deny of Humifortis (a block rule) is enforced by the
connector whatever the flow says; a flow without the deny step only relaxes the baseline CRITICAL deny.

Usage:
  KC_URL=https://sso.example.com KC_REALM=myrealm KC_ADMIN_USER=admin KC_ADMIN_PASSWORD=... \\
      python3 install_local_decision_flow.py [--bind]

KC_URL includes /auth when your Keycloak has it. With --bind the flow becomes the browser flow of the realm (the current
one is printed, to go back). Python 3.8+, standard library only.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def env(name):
    value = os.environ.get(name)
    if not value:
        sys.exit(f"{name} is required")
    return value


KC_URL = env("KC_URL").rstrip("/")
REALM = env("KC_REALM")
PREFIX = os.environ.get("FLOW_PREFIX", "hf-local-browser")
BASE = f"{KC_URL}/admin/realms/{urllib.parse.quote(REALM)}"


def request(method, url, body=None, form=None, token=None):
    data, headers = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as res:
            raw = res.read()
            return res.status, dict(res.headers), (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        sys.exit(f"{method} {url} -> HTTP {e.code}: {e.read().decode(errors='replace')[:300]}")


def token():
    _, _, body = request("POST", f"{KC_URL}/realms/master/protocol/openid-connect/token", form={
        "grant_type": "password", "client_id": "admin-cli",
        "username": env("KC_ADMIN_USER"), "password": env("KC_ADMIN_PASSWORD")})
    return body["access_token"]


TOKEN = token()


def api(method, path, body=None):
    return request(method, BASE + path, body=body, token=TOKEN)


def flow_executions(alias):
    return api("GET", f"/authentication/flows/{urllib.parse.quote(alias)}/executions")[2]


def set_requirement(parent, match, requirement):
    execution = next(e for e in flow_executions(parent) if match(e))
    execution["requirement"] = requirement
    api("PUT", f"/authentication/flows/{urllib.parse.quote(parent)}/executions", execution)


def add_execution(parent, provider, requirement, config=None):
    _, headers, _ = api("POST", f"/authentication/flows/{urllib.parse.quote(parent)}/executions/execution", {"provider": provider})
    execution_id = headers.get("Location", headers.get("location", "")).rsplit("/", 1)[-1]
    set_requirement(parent, lambda e: e["id"] == execution_id, requirement)
    if config:
        api("POST", f"/authentication/executions/{execution_id}/config", {"alias": f"{parent}-{provider}", "config": config})


def add_flow(parent, alias, requirement):
    api("POST", f"/authentication/flows/{urllib.parse.quote(parent)}/executions/flow",
        {"alias": alias, "type": "basic-flow", "provider": "registration-page-form", "description": ""})
    set_requirement(parent, lambda e: e.get("displayName") == alias, requirement)


def main():
    bind = "--bind" in sys.argv[1:]
    if any(f["alias"] == PREFIX for f in api("GET", "/authentication/flows")[2]):
        sys.exit(f"A flow named {PREFIX} already exists in realm {REALM}: remove it or set FLOW_PREFIX")

    api("POST", "/authentication/flows", {
        "alias": PREFIX, "description": "Humifortis: the flow decides (local decision source)",
        "providerId": "basic-flow", "topLevel": True, "builtIn": False})
    forms = f"{PREFIX}-forms"
    add_execution(PREFIX, "auth-cookie", "ALTERNATIVE")
    add_flow(PREFIX, forms, "ALTERNATIVE")
    add_execution(forms, "auth-username-password-form", "REQUIRED")
    add_execution(forms, "humifortis-device-collector", "REQUIRED")
    add_execution(forms, "humifortis-risk-authenticator", "REQUIRED", {"decision.source": "local"})
    add_flow(forms, f"{PREFIX}-deny", "CONDITIONAL")
    add_execution(f"{PREFIX}-deny", "humifortis-high-condition", "REQUIRED", {"outcome": "deny"})
    add_execution(f"{PREFIX}-deny", "humifortis-decision-report", "REQUIRED", {"outcome": "deny"})
    add_execution(f"{PREFIX}-deny", "deny-access-authenticator", "REQUIRED")
    add_flow(forms, f"{PREFIX}-mfa", "CONDITIONAL")
    add_execution(f"{PREFIX}-mfa", "humifortis-high-condition", "REQUIRED", {"outcome": "step_up"})
    add_execution(f"{PREFIX}-mfa", "humifortis-step-up-router", "REQUIRED")
    add_execution(forms, "humifortis-decision-report", "REQUIRED")
    print(f"Created the flow {PREFIX} in realm {REALM}.")

    if bind:
        current = api("GET", "")[2]["browserFlow"]
        api("PUT", "", {"browserFlow": PREFIX})
        print(f"Bound {PREFIX} as the browser flow. To go back, set the browser flow to '{current}' "
              "(Authentication > Flows > Action > Bind flow).")
    else:
        print(f"Not bound. Bind it from Authentication > Flows > {PREFIX} > Action > Bind flow, or run again with --bind.")


if __name__ == "__main__":
    main()
