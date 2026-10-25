# AGENTS.md — humifortis-keycloak-connector

Humifortis is a universal risk middleware for identity: it watches authentication events, scores the
risk of each entity (user, service account, agent) and returns or enforces a decision. This repository
is the Keycloak connector. This file is the contract for anyone — person or coding agent — who changes it.

## Where things are

| Path | Holds | Rule |
|---|---|---|
| `README.md`, `INSTALLATION.md`, `QUICKSTART.md`, `DOCKER.md`, `CHANGELOG.md` | What **is shipped**: install, configuration, run, release notes. | Describes current behaviour only. No plans. |
| `docs/roadmap.md` | The checklist: Now, Next, Shipped, each line linked to its issue. | Updated in the PR that changes it. |
| [`humifortis-core/specs/`](https://github.com/humifortis/humifortis-core/tree/develop/specs) | What is **proposed or being built**, including connector features (one `<topic>.spec.md` each, with a `Status:` line). | Specs live in core, not here. |

## The work cycle

1. **Issue before code.** Every change starts from a GitHub issue. Find it in the
   [Humifortis roadmap project](https://github.com/orgs/humifortis/projects/1) or the issue list.
   If none exists: a new idea first becomes a spec in humifortis-core (`Status: idea`), then an issue
   that links it, labelled `type:`, `priority:`, `theme:` and `stage:`; a bug gets a `type:bug` issue with
   the reproduction. Attach the issue to its epic as a sub-issue and add it to the project with the right Horizon.
2. **Branch from `develop`, PR into `develop`.** `main` receives releases only.
3. **Each PR closes and updates, in the same diff:**
   - the PR body says `Fixes #<n>` for every issue it finishes (`Refs #<n>` when it only advances one);
   - `docs/roadmap.md`: tick the line, or move it to Shipped when its epic is done;
   - the spec's `Status:` in humifortis-core moves (`ready` → `in-progress` → `done`);
   - the shipped docs (README, INSTALLATION, QUICKSTART, DOCKER.md) describe the new behaviour;
   - `CHANGELOG.md` (Keep a Changelog) gains an entry under `Unreleased`.
   A PR that ships behaviour without these is not done.
4. **Scope changes go back to the issue.** If the work turns out larger, smaller or different, edit the
   issue (and the spec) before or with the PR.
5. **Dropping work** closes the issue as *not planned* with one line why and removes the roadmap line.
6. **Keep the org roadmap in sync.** When a Now or Next entry is added, finished or dropped, update its
   Horizon in the project and the matching line in
   [`humifortis/.github/ROADMAP.md`](https://github.com/humifortis/.github/blob/main/ROADMAP.md).

## Architecture invariants

The pipeline is **Observe → Collect → Enrich → Detect → Score → Decide → Enforce → Alert**. This
connector is the **Enforce** stage, plus the entry point of Collect for Keycloak:

- It **captures Keycloak events** (event listener) and sends them to humifortis-core (Collect).
- At login it **calls core for a decision synchronously** and **applies ALLOW, STEP_UP or DENY**.
  This is the **only synchronous flow** of the platform: keep it fast and add nothing blocking that the
  decision does not need. The circuit breaker and retry in `client/` must keep protecting it.
- It **receives CAEP/SSF events** from core and acts on them.
- The connector stays thin: scoring, policies and thresholds live in core, never here.
- The Keycloak version is pinned in `pom.xml` (`keycloak.version`); the `KEYCLOAK_VERSION` ARG in the
  `Dockerfile` must match it.

## Checks before a PR

- `./mvnw -B clean verify` on JDK 17.
- `docker build .` when the `Dockerfile` changes.
- `CHANGELOG.md` updated.

## Writing issues

- English. Titles say the outcome, not the activity.
- Issue body: Context · Spec · Deliverables (checklist) · Acceptance · Pipeline stage.
