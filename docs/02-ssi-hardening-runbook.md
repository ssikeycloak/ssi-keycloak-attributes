# SSI Keycloak Authenticator - Hardening Runbook

## Overview

This runbook documents security hardening measures, operational procedures, and incident response guidelines for the SSI (Self-Sovereign Identity) Keycloak Authenticator.

**Version:** 1.1  
**Last Updated:** 2026-02-20  
**Applies to:** kodrat/keycloak-ssi-authenticator v1.0+

---

## Table of Contents

1. [Security Configuration](#security-configuration)
2. [Authentication & Authorization](#authentication--authorization)
3. [Logging & Monitoring](#logging--monitoring)
4. [Error Handling](#error-handling)
5. [Retry & Recovery](#retry--recovery)
6. [Incident Response](#incident-response)
7. [Deployment Checklist](#deployment-checklist)
8. [Rollback Procedures](#rollback-procedures)

---

## Security Configuration

### 1.1 Bearer Token Management

**Current State:**
- Bearer token stored in auth session notes
- Token masked in logs (e.g., `***oken`)

**Hardening Measures:**
```java
// Token is automatically redacted in logs
LOGGER.info("Token: " + LogSanitizer.redactToken(token));
// Output: Token: ***oken
```

**Recommended:**
- Rotate bearer tokens every 90 days
- Use short-lived tokens (1-24 hours TTL)
- Store tokens in secure vault (e.g., HashiCorp Vault) instead of config

### 1.2 Endpoint Security

**Status Endpoint (`/status`):**
- **Soft Mode** (Default): Logs unauthorized access but allows request
  ```bash
  # Current behavior - logs warning
  -Dssi.status.auth.soft.mode=true
  ```

- **Hard Mode**: Rejects unauthorized requests
  ```bash
  # Enable after validating clients
  -Dssi.status.auth.soft.mode=false
  ```

**Migration Path:**
1. Deploy with soft mode (default)
2. Monitor logs for 1-2 weeks
3. Ensure all legitimate clients send bearer tokens
4. Switch to hard mode
5. Update client applications that fail authentication

### 1.3 Session Security

**Session ID Handling:**
- Session IDs are masked in logs: `a1b2...c3d4`
- Connection IDs are masked: `conn...9xyz`
- QR codes do not contain sensitive data

---

## Authentication & Authorization

### 2.1 Flow Authentication

**Authenticator Flow (`SSIAuth`):**
- Requires valid Keycloak session
- Prevents duplicate flows via `ssi_flow_id` auth note
- Username masked in logs

**REST API Flow (`MyResourceProvider`):**
- Bearer token validation in `/status` endpoint
- Session validation required
- Soft/hard mode configurable

### 2.2 Configuration Keys

**Runtime Integration Mapping:**
- `did_method=web` -> walt.id OpenID4VC verifier endpoint
- `did_method=sov` -> Aries Cloud Agent (ACA-Py) admin endpoint

**Required:**
- `ssi_endpoint` - SSI agent URL
- `ssi_bearer_token` - Authentication token
- `did_method` - `sov` or `web`

**Optional:**
- `proof_request_json` - Schema and attributes
- `issuer_did` - Expected issuer validation
- `requested_credential` - Credential type specification

### 2.3 Config Compatibility

**Schema ID Formats:**
Both formats are now supported (backward compatible):
```json
// Format 1 (snake_case) - Preferred
{"schema_id": "...", "attributes": ["name"]}

// Format 2 (camelCase) - Legacy support
{"schemaId": "...", "attributes": ["name"]}
```

---

## Logging & Monitoring

### 3.1 Sensitive Data Redaction

**Automatic Redaction:**
- Bearer tokens: `***oken` or `[EMPTY]`
- Session/Connection IDs: `a1b2...c3d4`
- Request payloads: `[REDACTED]`
- Verified claims: `[REDACTED]`
- Exception messages: Sanitized

**Log Levels:**
- `INFO`: Flow progress, masked identifiers
- `FINE`: Detailed steps (no sensitive data)
- `WARNING`: Retryable issues
- `SEVERE`: Critical errors (sanitized)

### 3.2 Monitoring Checklist

**Key Metrics:**
```
# Connection success rate
[DIDSov] Connection established: conn...9xyz

# Proof request timing
[DIDSov] Proof request sent: pres...exid

# Verification outcomes
[DIDSov] Verification successful - N attributes revealed
[DIDSov] Verification failed - State: ...

# Auth failures
[MyResourceProvider] Bearer token authentication failed
[MyResourceProvider] /status accessed without auth (soft mode)
```

**Alert Conditions:**
- Multiple connection timeouts → Network/SPI agent issue
- Frequent verification failures → Schema/credential mismatch
- Unauthorized access attempts (hard mode) → Security incident

### 3.3 Audit Trail

**Evidence Structure:**
```json
{
  "type": "document",
  "method": "didcomm/present-proof",
  "time": "2026-02-16T10:30:00Z",
  "document_details": {
    "type": "identity_card",
    "issuer": {
      "name": "did:sov:issuer",
      "country": "ID"
    }
  }
}
```

---

## Error Handling

### 4.1 Error Codes

**Structure:** `SSI-XXXX` (e.g., `SSI-1001`)

**Categories:**
- **1xxx**: Configuration errors (not retryable)
- **2xxx**: Network errors (retryable)
- **3xxx**: Flow/State errors (not retryable)
- **4xxx**: DIDComm errors (some retryable)
- **5xxx**: Authentication errors (not retryable)
- **9xxx**: Internal errors (not retryable)

**Common Codes:**
| Code | Description | Action |
|------|-------------|--------|
| SSI-1001 | Missing endpoint | Check realm config |
| SSI-1002 | Missing token | Update authenticator config |
| SSI-2001 | Connection timeout | Check agent availability |
| SSI-2002 | Connection refused | Start agent service |
| SSI-3001 | Invalid state | Restart flow |
| SSI-4001 | Invitation failed | Retry (max 3) |
| SSI-4005 | Verification failed | Check schema match |
| SSI-5001 | Unauthorized | Provide valid token |

### 4.2 Exception Types

**SSIFlowException:**
```java
try {
    // SSI operation
} catch (SSIFlowException e) {
    // Check retryability
    if (e.isRetryable()) {
        // Retry with backoff
    }
    // Log with error code
    LOGGER.error("Flow error: " + e.getCode());
}
```

### 4.3 Recovery Procedures

**Connection Timeout:**
1. Check if agent is running: `curl http://agent:port/status`
2. Verify network connectivity
3. Check agent logs
4. Retry flow (state preserved)

**Verification Failure:**
1. Check schema ID matches credential
2. Verify issuer DID
3. Check requested attributes exist in credential
4. Review credential format (jwt_vc_json vs indy)

**Session Expired:**
1. User must restart authentication
2. Previous session data cleared
3. New QR code generated

**SSI Verified But Claim Missing in Token:**
1. Confirm SSI flow success in logs (`[SSIAuth] Step 4: Verification successful`)
2. Confirm save log exists (`[AttributeUtil] verified_claims saved`)
3. In Keycloak Client Scope mapper, verify exact values:
   - Mapper Type: `User Session Note`
   - User Session Note: `verified_claims`
   - Token Claim Name: `verified_claims`
   - Claim JSON Type: `JSON`
   - Add to ID token: `ON`
4. Ensure that client scope is attached to requesting client
5. Re-login with fresh session and decode a newly issued ID token

---

## Retry & Recovery

### 5.1 Retry Endpoint

**New in v1.1:** The `/retry` endpoint allows in-flow recovery without full login restart.

**Endpoint:** `POST /realms/{realm}/custom-resource/retry`

**Request:**
```bash
curl -X POST "http://keycloak:8080/realms/myrealm/custom-resource/retry" \
  -d "sessionId=<session-id>" \
  -d "tabId=<tab-id>"
```

**Response (Success):**
```json
{
  "status": "reset-ok",
  "reasonCode": "reset_ok",
  "flowId": "new-uuid",
  "previousStatus": "invalid",
  "message": "SSI flow reset successfully. Ready to retry.",
  "nextStep": "poll",
  "recoverable": true
}
```

**Response (Session Expired):**
```json
{
  "status": "error",
  "reasonCode": "session_expired",
  "message": "Session has expired. Please restart login.",
  "recoverable": false
}
```

### 5.2 Reason Codes

**Status responses now include machine-readable reason codes:**

| Reason Code | Description | Recoverable | UI Action |
|-------------|-------------|-------------|-----------|
| `success` | Operation completed | No | Continue |
| `in_progress` | Flow in progress | Yes | Continue polling |
| `reset_ok` | Retry successful | Yes | Restart polling |
| `timeout` | Polling timeout | Yes | Show retry button |
| `invalid` | Verification failed | Yes | Show retry button |
| `session_expired` | Session expired | No | Restart login |
| `invalid_tab` | Invalid tab ID | No | Restart login |
| `unauthorized` | Auth required | No | Show error |
| `missing_params` | Missing parameters | No | Fix request |
| `internal_error` | Server error | No | Contact support |

**Frontend Integration:**
```javascript
// Check if error is recoverable
if (data.recoverable === true) {
    showRetryButton();
} else if (data.reasonCode === 'session_expired') {
    redirectToLogin();
}
```

### 5.3 Retry Flow States

**State Diagram:**
```
[Start] → [waiting-connection] → [connected] → [waiting-presentation] → [done]
    ↓            ↓                    ↓                ↓
    └────────────┴────────────────────┴────────────────┴→ [invalid/timeout]
                                                          ↓
                                                    [retry endpoint]
                                                          ↓
                                                    [reset-ok]
                                                          ↓
                                                    [waiting-connection]
```

**Reset Behavior:**
- All transient session notes are cleared
- New `flowId` is generated
- Previous `verified_claims` are cleared (privacy)
- Config notes (endpoint, token, DID method) are preserved

### 5.4 Correlation Logging

**Structured log format for end-to-end tracing:**
```
[SSI-FLOW] event=retry session=a1b2...c3d4 tab=x7y8...z9w0 ts=2026-02-20T10:30:00Z msg="Retry requested by user" previousStatus=invalid
```

**Event Types:**
- `start` - Flow started
- `wait` - Waiting for connection/presentation
- `connect` - Connection established
- `proof-request` - Proof request sent
- `verify` - Presentation verification
- `retry` - User requested retry
- `reset` - Flow state reset
- `success` - Flow completed successfully
- `failure` - Flow failed
- `timeout` - Polling timeout
- `terminal` - Non-recoverable error

**Log Search Examples:**
```bash
# Find all retry events for a session
grep "event=retry session=a1b2" /var/log/keycloak/server.log

# Find all failures in last hour
grep "event=failure" /var/log/keycloak/server.log | tail -100

# Trace full flow for a tab
grep "tab=x7y8" /var/log/keycloak/server.log | grep SSI-FLOW
```

### 5.5 Troubleshooting Matrix

| Symptom | Likely Cause | Check | Resolution |
|---------|--------------|-------|------------|
| QR not scanned | Wallet not responding | Agent logs | Check wallet app |
| Connection timeout | Agent unreachable | `curl agent:8021/status` | Restart agent |
| Proof not received | Credential mismatch | Schema ID config | Verify schema |
| Verification failed | Invalid credential | Issuer DID config | Check issuer |
| Retry not working | Session expired | `reasonCode` in response | Restart login |
| Claims missing in token | Mapper not configured | Admin console | Add mapper |
| Polling stuck | Tab ID mismatch | URL params | Check tabId |

---

## Incident Response

### 6.1 Security Incident Types

**P1 - Critical:**
- Unauthorized access to `/status` (hard mode)
- Token leakage in logs
- Session hijacking

**P2 - High:**
- Multiple verification failures
- Agent unavailability
- Config parsing errors

**P3 - Medium:**
- Slow response times
- Intermittent timeouts

### 6.2 Response Procedures

**Unauthorized Access Detected:**
```bash
# Check logs for pattern
grep "Unauthorized access attempt" /var/log/keycloak/ssi.log

# Identify source IP
# Review if legitimate client or attack

# If attack:
# 1. Enable hard mode immediately
# 2. Block source IP at firewall
# 3. Rotate bearer token
# 4. Audit all sessions
```

**Token Leakage Suspected:**
```bash
# Search logs for raw tokens
grep -i "bearer.*eyJ" /var/log/keycloak/ssi.log

# If found:
# 1. Rotate token immediately
# 2. Update all client configurations
# 3. Review log configuration
# 4. Verify LogSanitizer is working
```

**Agent Unavailable:**
```bash
# Check agent health
curl -f http://agent:8021/status || echo "AGENT DOWN"

# Restart procedure:
# 1. Notify users of maintenance
# 2. Restart agent service
# 3. Verify /connections endpoint
# 4. Resume operations
```

---

## Deployment Checklist

### 7.1 Pre-Deployment

- [ ] All unit tests pass: `mvn test`
- [ ] No compilation errors: `mvn clean compile`
- [ ] Log redaction verified in test output
- [ ] Bearer token configured in realm
- [ ] SSI endpoint reachable from Keycloak
- [ ] Schema ID validated against agent

### 7.2 Deployment Steps

1. **Backup current deployment**
   ```bash
   cp keycloak-ssi-authenticator.jar keycloak-ssi-authenticator.jar.bak
   ```

2. **Deploy new version**
   ```bash
   cp target/kodrat.keycloak-ssi-authenticator.jar $KEYCLOAK/providers/
   ```

3. **Configure soft mode** (initial)
   ```bash
   # Add to JAVA_OPTS
   -Dssi.status.auth.soft.mode=true
   ```

4. **Restart Keycloak**
   ```bash
   $KEYCLOAK/bin/kc.sh restart
   ```

5. **Verify deployment**
   ```bash
   # Check provider loaded
   grep "SSI" $KEYCLOAK/logs/server.log
   
   # Test status endpoint
   curl "http://keycloak:8080/realms/master/ssi/status?sessionId=test&tabId=test"
   ```

### 7.3 Post-Deployment

- [ ] Monitor logs for 1 hour
- [ ] Verify no sensitive data in logs
- [ ] Check authentication success rate
- [ ] Verify soft mode logging unauthorized requests
- [ ] Plan hard mode migration

---

## Rollback Procedures

### 8.1 Quick Rollback

**If critical issue detected:**
```bash
# 1. Stop Keycloak
$KEYCLOAK/bin/kc.sh stop

# 2. Restore previous JAR
cp keycloak-ssi-authenticator.jar.bak $KEYCLOAK/providers/kodrat.keycloak-ssi-authenticator.jar

# 3. Restart
$KEYCLOAK/bin/kc.sh start

# 4. Verify
# Check logs for successful startup
```

### 8.2 Config Rollback

**If config issue:**
```bash
# Revert to previous authenticator config via Keycloak Admin Console
# 1. Navigate to Realm → Authentication → Flows
# 2. Edit SSI authenticator configuration
# 3. Restore previous endpoint/token values
```

### 8.3 Verification After Rollback

- [ ] Application starts without errors
- [ ] Authenticator flow works
- [ ] REST API responds correctly
- [ ] No regression in functionality

---

## Appendix

### A. Environment Variables

```bash
# JVM Options
export JAVA_OPTS="-Dssi.status.auth.soft.mode=true"

# Keycloak Configuration
export KEYCLOAK_OPTS="--spi-authenticator-ssi-enabled=true"
```

### B. Log Locations

```
# Keycloak logs
/var/log/keycloak/server.log

# SSI-specific logs (if configured)
/var/log/keycloak/ssi.log

# System logs
/var/log/messages
```

### C. Useful Commands

```bash
# Monitor SSI logs in real-time
tail -f /var/log/keycloak/server.log | grep -E "(DIDSov|DIDWeb|SSIAuth|MyResourceProvider)"

# Check authenticator config
$KEYCLOAK/bin/kc.sh show-config | grep ssi

# Test agent connectivity
curl -H "Authorization: Bearer $TOKEN" http://agent:8021/connections

# Verify JAR contents
jar tf $KEYCLOAK/providers/kodrat.keycloak-ssi-authenticator.jar | grep -E "(DIDSov|DIDWeb)"
```

---

## Contact Information

**Development Team:** kodrat  
**Repository:** github.com/kodrat/keycloak-ssi-authenticator  
**Issue Tracker:** Use GitHub Issues

---

**Document Control:**
- Review every 3 months
- Update on major version releases
- Track changes in CHANGELOG.md
