# SSI Keycloak Module Usage Guide

This document explains how to use `kodrat.keycloak-ssi-authenticator` for SSI-based login/identity verification (`did:web` or `did:sov`) in Keycloak.

Agent mapping used in this module:
- `did:web` -> **walt.id** (OpenID4VC verifier)
- `did:sov` -> **Aries Cloud Agent (ACA-Py)** (DIDComm present-proof)


## Requirements

### Build environment

| Requirement | Version | Notes |
|---|---|---|
| JDK | 17 | Required, matches `maven.compiler.release` in `pom.xml` |
| Maven | 3.8+ | To build the JAR |
| Git | - | To clone the repo |

### Runtime environment

| Requirement | Version | Notes |
|---|---|---|
| Keycloak | 24.x | SPI BOM used: `keycloak-spi-bom 24.0.0` |
| Docker | - | If Keycloak runs in a container |

### SSI backend (depending on the chosen DID method)

Pick one (or both):

- **walt.id verifier** for `did:web`
  - Verifier endpoint URL (HTTPS recommended)
  - Bearer token (optional, depending on verifier configuration)
  - Allowed issuer DID
  - Definition of the credential to request (type + attributes)

- **Aries Cloud Agent (ACA-Py)** for `did:sov`
  - ACA-Py admin endpoint URL
  - Bearer token / API key (optional)
  - Allowed issuer DID (will be matched against the proof metadata)
  - `schema_id` and the list of attributes to request

### Keycloak access

- Admin account for the target realm (to configure flow, client scope, mapper, and client)
- Target realm already created
- Target OIDC client already created


## 1) Module Summary

- **Authenticator ID**: `ssi-authenticator`
- **Realm REST Provider ID**: `custom-resource`
- **Status polling endpoint**: `/realms/{realm}/custom-resource/status`
- **Active consent template**: `login-identity-consent.ftl` (static English text)

## 2) Build and Deploy JAR

### Build
```bash
mvn clean package -DskipTests
```

JAR output:
- `target/kodrat.keycloak-ssi-authenticator.jar`

### Deploy to Keycloak container
Note: in this environment, the provider JAR is mounted to `/opt/keycloak/providers/kodrat.keycloak-ssi-authenticator.jar`, so you only need to rebuild the JAR and restart the Keycloak process in the container.

```bash
# stop Keycloak process inside the container
docker exec ssi-keycloak /bin/sh -c "kill 1"

# start container again
docker start ssi-keycloak
```

> Avoid `docker down` unless necessary.

## 3) Keycloak Configuration

Go to:
- **Authentication** -> **Flows** -> active login flow -> execution `SSI Authentication` -> **Config**

Main configuration fields:

1. `did_method`
   - `web` (walt.id) or `sov` (Aries Cloud Agent / ACA-Py)
2. `ssi_endpoint`
   - SSI verifier/agent URL
3. `ssi_bearer_token`
   - SSI API access token
4. `issuer_did`
   - Allowed issuer DID

If `did_method = sov` (Aries Cloud Agent / ACA-Py):
5. `proof_request_json`
   - Example:
   ```json
    {"schema_id":"did:sov:issuer:KYC:1.0","attributes":["name","NIK","email","phone"]}
    ```

 6. `issuer_did` (recommended and now enforced when set)
    - If configured, DID:SOV verification will only pass when issuer extracted from proof metadata matches this value.
    - Supports matching between `did:sov:<issuer>` and legacy `<issuer>` identifier formats.

If `did_method = web` (walt.id):
6. `credential_type`
   - Example: `jwt_w3c_vc`
7. `requested_credential`
   - Example:
   ```json
   {"credential_type":"EducationalID","attributes":["name","school","student_id"]}
   ```

## 4) Runtime Flow (High-Level)

1. User opens Keycloak login.
2. SSI authenticator renders consent + QR page.
3. Wallet scans QR / authorizes.
4. Frontend polls endpoint:
   - `GET /realms/{realm}/custom-resource/status?sessionId=...&tabId=...`
5. On successful verification, login flow continues.

## 4.1 Make `verified_claims` Appear in ID Token (REQUIRED)

This module stores SSI result data in a **session note** using key `verified_claims`.
To include it in issued tokens, add a mapper in Keycloak.

Location:
- **Realm** -> **Client Scopes** -> select scope (example: `ssi-claims`) -> **Mappers** -> **Add mapper**

Mapper fields (Keycloak 24):
- `Mapper Type`: `User Session Note`
- `Name`: `verified_claims`
- `User Session Note`: `verified_claims`
- `Token Claim Name`: `verified_claims`
- `Claim JSON Type`: `JSON`
- `Add to ID token`: `ON` (required)
- `Add to access token`: `OFF` (optional, set `ON` if needed)
- `Add to userinfo`: `OFF` (optional)

Then attach the scope to target client:
- **Clients** -> select client (example: `unja`) -> **Client Scopes**
- Add `ssi-claims` to **Default Client Scopes** (recommended)

Expected ID token snippet:
```json
{
  "verified_claims": {
    "verification": {
      "evidence": [...],
      "assurance_level": "high",
      "trust_framework": null
    },
    "claims": {
      "name": "..."
    }
  }
}
```

## 5) Polling Endpoint Example

```bash
curl "http://localhost:8080/realms/master/custom-resource/status?sessionId=<SESSION_ID>&tabId=<TAB_ID>"
```

Example response:
```json
{"status":"waiting-connection","qrCodeUrl":"...","message":"..."}
```
or
```json
{"status":"done","connectionId":"...","message":"..."}
```

## 6) `/status` Endpoint Auth Mode

Controlled by system property:

- **Soft mode** (default):
  - `-Dssi.status.auth.soft.mode=true`
  - requests without bearer token are still processed (and logged)

- **Hard mode**:
  - `-Dssi.status.auth.soft.mode=false`
  - requests without bearer token return `401 Unauthorized`

## 7) Troubleshooting

### A. Consent UI text does not change
Checklist:
1. Ensure flow uses `login-identity-consent.ftl` (not `login-sms.ftl`).
2. Ensure latest JAR is rebuilt and Keycloak is restarted.
3. Try incognito / hard refresh.

### B. Requested data stays default (`name`, `NIK`, `email`, `phone`)
Common cause:
- Empty or malformed JSON config.

Check:
- for `sov`: `proof_request_json.attributes`
- for `web`: `requested_credential.attributes`

### C. Verification remains in waiting state
Check:
1. `ssi_endpoint` is correct and reachable from Keycloak container.
2. `ssi_bearer_token` is valid.
3. Wallet actually submits proof/presentation.
4. Keycloak logs for timeout/connection errors.

### E. DID:SOV verification fails with issuer mismatch
Common log pattern:
- `issuer_did mismatch - expected: ..., got: ...`

Checklist:
1. Ensure `issuer_did` in Keycloak config matches ACA-Py credential issuer DID.
2. If your agent returns legacy issuer format (without `did:sov:` prefix), keep logical issuer value identical.
3. Check proof metadata (`schema_id`/`cred_def_id`) from agent response.

### D. Verification succeeds but `verified_claims` is missing in token
Most common cause: mapper not configured or wrong mapper key.

Checklist:
1. Mapper type = `User Session Note`
2. User Session Note = `verified_claims`
3. Token Claim Name = `verified_claims`
4. Claim JSON Type = `JSON`
5. `Add to ID token` = `ON`
6. Mapper client scope is attached to token-requesting client
7. Re-login with a fresh session, then decode a newly issued token

## 8) Important File References

- `src/main/java/kodrat/keycloak/authenticator/SSIAuthFactory.java`
- `src/main/java/kodrat/keycloak/authenticator/SSIAuth.java`
- `src/main/java/kodrat/keycloak/provider/MyResourceProvider.java`
- `src/main/java/kodrat/keycloak/config/ConfigUtils.java`
- `src/main/resources/theme-resources/templates/login-identity-consent.ftl`
- `docs/02-ssi-hardening-runbook.md`

## 9) Operational Notes

- Use `mvn clean package -DskipTests` for fast deploy build.
- For safer pre-release verification, run:
```bash
mvn test
```
- Avoid logging sensitive data; module already uses `LogSanitizer` to mask tokens/identifiers.
