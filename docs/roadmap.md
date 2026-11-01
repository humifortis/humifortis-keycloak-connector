# Roadmap

The checklist for this repository. Org-wide view: [`humifortis/.github/ROADMAP.md`](https://github.com/humifortis/.github/blob/main/ROADMAP.md);
planning board: [Humifortis roadmap project](https://github.com/orgs/humifortis/projects/1). Specs live in
[humifortis-core/specs](https://github.com/humifortis/humifortis-core/tree/develop/specs).

## Now

### [Align develop with main and make develop the default (#5)](https://github.com/humifortis/humifortis-keycloak-connector/issues/5)
- [ ] Merge `main` (21 commits) into `develop` (#10)
- [ ] Switch default branch to `develop` (#11)

### [Repository organisation (#6)](https://github.com/humifortis/humifortis-keycloak-connector/issues/6)
- [ ] Add `docs/roadmap.md` (#12)
- [ ] Add `AGENTS.md` and `CLAUDE.md` pointer (#13)
- [ ] Restore the `docs/` folder the CHANGELOG links to (#14)

### [Ready for the 10-minute quickstart (#7)](https://github.com/humifortis/humifortis-keycloak-connector/issues/7)
- [ ] Realm export with the Humifortis authenticator, event listener and `humifortis` theme (#15)
- [ ] Local mode: provision the API key automatically in the quickstart (#16)
- [ ] Release workflow: jar + image on `v*` tags; fix the release URL (#17)
- [ ] One Keycloak version everywhere (#18)
- [ ] Reconcile versions (README 1.0.0, release v1.0.1, pom 1.1.0) (#19)

## Next

### [Synchronous enforcement and SDK-grade client (#8)](https://github.com/humifortis/humifortis-keycloak-connector/issues/8)
- [ ] gRPC client for the decision call (#20)
- [ ] AAuth / agent support beyond token exchange and CIBA (#21)
- [ ] Validate: synchronous enforcement at login (DENY / STEP_UP / ALLOW, DPoP evidence) (#22)

## Shipped

- Authenticators (risk-based decision at login: ALLOW, STEP_UP, DENY)
- Event listener (Keycloak events sent to Humifortis)
- CAEP/SSF receiver
- DPoP evidence (thumbprint of the key a token request proved)
- Service-account and delegation (token exchange) executors
- Login theme and device collector
