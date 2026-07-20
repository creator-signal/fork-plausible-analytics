# Creator Signal ZITADEL SSO

This fork adds a standalone OIDC integration for the Community Edition build. The feature lives under the `CreatorSignal.PlausibleSSO` namespace and uses its own routes and database tables. It does not use Plausible's `extra/` source tree, Enterprise SSO tables, `/sso/*` routes or `SSO_ENABLED` flag.

## Authentication flow

The integration uses the OIDC Authorization Code flow with PKCE, state and nonce validation. It discovers ZITADEL endpoints from the configured issuer and validates:

- the discovery issuer and endpoint origins;
- the ID-token signature against ZITADEL's JWKS;
- the `iss`, `aud`, `azp`, `exp`, `iat`, `nonce` and optional `at_hash` claims;
- a verified email address; and
- the configured ZITADEL project role before provisioning a Plausible user.

Only `RS256` ID tokens are accepted. Provider endpoints must use the same origin as the configured issuer. HTTPS is mandatory unless the explicit local-development override is enabled.

## ZITADEL application

Create a Web OIDC application with:

- Authorization Code enabled;
- PKCE using `S256`;
- redirect URI `${BASE_URL}/creator-signal/sso/callback`;
- scopes `openid profile email` and `urn:zitadel:iam:org:project:role:platform:operator`;
- project roles asserted in the ID token; and
- the `platform:operator` project role assigned only to platform operators.

The Sales Pulse infrastructure reconciler owns creation and updates of this ZITADEL application. The client ID, and optional client secret, are supplied to the Plausible deployment through OpenBao-backed environment configuration.

## Configuration

| Variable                                     |     Required | Default                             | Purpose                                                                               |
| -------------------------------------------- | -----------: | ----------------------------------- | ------------------------------------------------------------------------------------- |
| `CREATOR_SIGNAL_SSO_ENABLED`                 |           No | `false`                             | Enables the standalone login and callback routes.                                     |
| `CREATOR_SIGNAL_SSO_ISSUER`                  | When enabled | —                                   | Exact ZITADEL issuer URL.                                                             |
| `CREATOR_SIGNAL_SSO_CLIENT_ID`               | When enabled | —                                   | ZITADEL OIDC application client ID.                                                   |
| `CREATOR_SIGNAL_SSO_CLIENT_SECRET`           |           No | —                                   | Optional Web-client secret. PKCE is always used.                                      |
| `CREATOR_SIGNAL_SSO_BOOTSTRAP_EMAIL`         | When enabled | —                                   | The only operator allowed to initialise the Plausible team.                           |
| `CREATOR_SIGNAL_SSO_REQUIRED_ROLE`           |           No | `platform:operator`                 | Required ZITADEL role.                                                                |
| `CREATOR_SIGNAL_SSO_ROLE_CLAIM`              |           No | `urn:zitadel:iam:org:project:roles` | ID-token claim containing roles.                                                      |
| `CREATOR_SIGNAL_SSO_TEAM_NAME`               |           No | `Creator Signal`                    | Name assigned to the bootstrapped team.                                               |
| `CREATOR_SIGNAL_SSO_DEFAULT_TEAM_ROLE`       |           No | `admin`                             | Plausible role for later operators: `viewer`, `editor` or `admin`.                    |
| `CREATOR_SIGNAL_SSO_SESSION_TIMEOUT_MINUTES` |           No | `720`                               | Fixed linked-user session lifetime, from 5 minutes to a maximum of 12 hours.          |
| `CREATOR_SIGNAL_SSO_SCOPES`                  |           No | `openid profile email`              | Additional comma- or space-separated scopes. The required-role scope is always added. |
| `CREATOR_SIGNAL_SSO_FORCE_LOGIN`             |           No | `false`                             | Redirects `/login` to ZITADEL.                                                        |
| `CREATOR_SIGNAL_SSO_ALLOW_INSECURE_HTTP`     |           No | `false`                             | Allows an HTTP issuer for local development only.                                     |

For a local ZITADEL instance, a typical configuration is:

```dotenv
CREATOR_SIGNAL_SSO_ENABLED=true
CREATOR_SIGNAL_SSO_ISSUER=http://auth.localhost:48080
CREATOR_SIGNAL_SSO_CLIENT_ID=replace-from-reconciler
CREATOR_SIGNAL_SSO_BOOTSTRAP_EMAIL=operator@example.test
CREATOR_SIGNAL_SSO_REQUIRED_ROLE=platform:operator
CREATOR_SIGNAL_SSO_FORCE_LOGIN=true
CREATOR_SIGNAL_SSO_ALLOW_INSECURE_HTTP=true
DISABLE_REGISTRATION=true
```

Do not enable the insecure HTTP override outside local development.

## Provisioning and access

The first successful login must use `CREATOR_SIGNAL_SSO_BOOTSTRAP_EMAIL`. That operator is linked to a persistent `{issuer, subject}` identity, becomes the owner of the automatically created Creator Signal team, and completes initial team setup.

Later authorised operators are created just in time and added to the same team with the configured role. A user missing `platform:operator` is rejected before any Plausible user or membership is created.

Linked users cannot use Plausible password login or password reset. One existing, unlinked local owner should be retained for break-glass access. When forced login is enabled, its explicit entry point is:

```text
/login?local=true
```

Linked-user sessions have a fixed timeout and are not extended by activity. Removing the ZITADEL role prevents the next login; existing sessions expire within the configured timeout.

## Container releases

The existing public-image workflow is repurposed for this fork so the repository keeps a single public container pipeline. Pushing a release tag such as `v3.2.1-cs.1` publishes a multi-architecture image to:

```text
ghcr.io/creator-signal/plausible:3.2.1-cs.1
```

The build remains `MIX_ENV=ce`, publishes by immutable digest, and attaches SBOM and provenance attestations. Deployments should pin the manifest digest rather than a mutable tag.
