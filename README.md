# Keycloak SSI Authenticator

A custom Keycloak authenticator for SSI (Self-Sovereign Identity) based identity verification using DID + Verifiable Credentials.

## Overview

This module provides:
- Authenticator SPI: `ssi-authenticator`
- Realm REST extension: `custom-resource`
- SSI verification flow with QR code + status polling
- DID method support:
  - `did:web` via **walt.id** (OpenID4VC verifier flow)
  - `did:sov` via **Aries Cloud Agent (ACA-Py)** (DIDComm present-proof flow)

## Main Components

- `src/main/java/kodrat/keycloak/authenticator/SSIAuthFactory.java`
  - Provider registration for `ssi-authenticator`
  - Authenticator configuration field definitions

- `src/main/java/kodrat/keycloak/authenticator/SSIAuth.java`
  - SSI login flow orchestration
  - Consent page + QR page rendering

- `src/main/java/kodrat/keycloak/provider/MyResourceProviderFactory.java`
- `src/main/java/kodrat/keycloak/provider/MyResourceProvider.java`
  - REST endpoint for status polling: `/realms/{realm}/custom-resource/status`

- `src/main/java/kodrat/keycloak/api/DIDWeb.java`
- `src/main/java/kodrat/keycloak/api/DIDSov.java`
  - DID method-specific flow implementations

- `src/main/resources/theme-resources/templates/login-identity-consent.ftl`
  - UI template for consent + QR display
  - Currently uses static English text

## Keycloak Configuration

In the `SSI Authentication` execution, configure the following fields:

Required:
- `did_method` -> `web` or `sov`
- `ssi_endpoint`
- `ssi_bearer_token` (optional depending on endpoint)
- `issuer_did`

If `did_method = sov` (Aries Cloud Agent / ACA-Py):
- `proof_request_json`
  - Example:
  ```json
  {"schema_id":"did:sov:issuer:KYC:1.0","attributes":["name","NIK","email","phone"]}
  ```

If `did_method = web` (walt.id):
- `credential_type` (e.g., `jwt_w3c_vc`)
- `requested_credential`
  - Example:
  ```json
  {"credential_type":"EducationalID","attributes":["name","school","student_id"]}
  ```

## Build

```bash
mvn clean package -DskipTests
```

Output:
- `target/kodrat.keycloak-ssi-authenticator.jar`

## Deploy to Keycloak Container

In this environment, the provider JAR is mounted to the container, so simply rebuild the JAR and restart the Keycloak process.

```bash
# Stop Keycloak process inside container
docker exec ssi-keycloak /bin/sh -c "kill 1"

# Start container again
docker start ssi-keycloak
```

Note: Avoid `docker down` unless necessary.

## Polling Endpoint

```http
GET /realms/{realm}/custom-resource/status?sessionId={sessionId}&tabId={tabId}
```

Example responses:
```json
{"status":"waiting-connection","qrCodeUrl":"...","message":"..."}
```

```json
{"status":"done","connectionId":"...","message":"..."}
```

## Auth Mode for `/status`

Controlled by system property:
- Soft mode (default): `-Dssi.status.auth.soft.mode=true`
- Hard mode: `-Dssi.status.auth.soft.mode=false`

## Documentation

- `docs/01-ssi-keycloak-usage-guide.md` - Operational guide
- `docs/02-ssi-hardening-runbook.md` - Hardening and incident runbook
