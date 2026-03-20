# Auth Notes Inventory

This document catalogs all authentication session notes (auth notes) used by DID methods.

## DIDWeb Auth Notes

| Key | Constant | Set By | Read By | Description |
|-----|----------|--------|---------|-------------|
| `ssi_status` | `SSISessionConstants.SSI_STATUS` | handleAuthentication, sendProofRequest, isVerified | SSIFlowOrchestrator, MyResourceProvider | Current flow status |
| `ssi_state_id` | `SSISessionConstants.SSI_STATE_ID` | sendProofRequest | isVerified, hasReceivedPresentationRestApi | OpenID4VC state ID |
| `verification_url` | `SSISessionConstants.VERIFICATION_URL` | sendProofRequest | handleAuthentication, hasReceivedPresentationRestApi | Authorization URL |
| `invitation_url` | `SSISessionConstants.INVITATION_URL` | sendProofRequest | handleAuthentication, hasReceivedPresentationRestApi | Same as verification_url |
| `qr_code_url` | `SSISessionConstants.QR_CODE_URL` | sendProofRequest | handleAuthentication | QR code data URL |
| `ssi_endpoint` | `SSISessionConstants.SSI_ENDPOINT` | handleAuthentication | verifyPresentation (session) | Agent endpoint |
| `ssi_bearer_token` | `SSISessionConstants.SSI_BEARER_TOKEN` | handleAuthentication | verifyPresentation (session) | Auth token |
| `ssi_token` | `SSISessionConstants.SSI_TOKEN` | DIDMethodFactory | ConfigUtils | Legacy token key |
| `bearer_token` | (deprecated) | DIDMethodFactory | ConfigUtils | Legacy fallback |
| `ssi_failure_reason` | (no constant) | isVerified, hasReceivedPresentationRestApi | MyResourceProvider | Failure reason |
| `subject_did` | (no constant) | DIDMethodFactory | extractCredentialAttributes | Expected subject DID |
| `issuer_did` | (no constant) | DIDMethodFactory | extractCredentialAttributes | Expected issuer DID |
| `requested_credential` | (no constant) | DIDMethodFactory | extractCredentialAttributes | Credential config JSON |

## DIDSov Auth Notes

| Key | Constant | Set By | Read By | Description |
|-----|----------|--------|---------|-------------|
| `ssi_status` | `SSISessionConstants.SSI_STATUS` | handleAuthentication, isConnectionEstablished, sendProofRequest | SSIFlowOrchestrator, MyResourceProvider | Current flow status |
| `connection_id` | `SSISessionConstants.CONNECTION_ID` | isConnectionEstablished | sendProofRequest, mapConnectionIdToUserAttribute | DIDComm connection ID |
| `invitation_url` | `SSISessionConstants.INVITATION_URL` | handleAuthentication | isConnectionEstablished | OOB invitation URL |
| `invi_msg_id` | `SSISessionConstants.INVI_MSG_ID` | handleAuthentication | isConnectionEstablished | Invitation message ID |
| `pres_ex_id` | `SSISessionConstants.PRES_EX_ID` | sendProofRequest | hasReceivedPresentation, verifyPresentation | Presentation exchange ID |
| `qr_code_url` | `SSISessionConstants.QR_CODE_URL` | handleAuthentication | - | QR code data URL |
| `ssi_endpoint` | `SSISessionConstants.SSI_ENDPOINT` | handleAuthentication | verifyPresentation (session) | Agent endpoint |
| `ssi_bearer_token` | `SSISessionConstants.SSI_BEARER_TOKEN` | handleAuthentication | verifyPresentation (session) | Auth token |
| `oob_qr_shown_at` | `SSISessionConstants.OOB_QR_SHOWN_AT` | handleAuthentication | isConnectionEstablished | QR display timestamp |
| `oob_qr_scanned_at` | `SSISessionConstants.OOB_QR_SCANNED_AT` | markScanIfNeeded | - | QR scan timestamp |
| `sov_accept_conn_id` | `SSISessionConstants.SOV_ACCEPT_CONN_ID` | maybeAcceptConnection | maybeAcceptConnection | Connection being accepted |
| `sov_accept_last_at` | `SSISessionConstants.SOV_ACCEPT_LAST_AT` | maybeAcceptConnection | maybeAcceptConnection | Last accept attempt time |
| `sov_accepted_conn_id` | `SSISessionConstants.SOV_ACCEPTED_CONN_ID` | maybeAcceptConnection | maybeAcceptConnection | Successfully accepted conn |
| `sov_referent_mapping` | (no constant) | sendProofRequestInternal | mapReferentsToAttributeNames | Referent to attr name map |
| `ssi_failure_reason` | `SSISessionConstants.SSI_FAILURE_REASON` | verifyPresentation | MyResourceProvider | Failure reason |
| `proof_request_json` | `SSISessionConstants.PROOF_REQUEST_JSON` | DIDMethodFactory | sendProofRequestInternal | Proof request config |
| `subject_did` | (no constant) | DIDMethodFactory | - | Expected subject DID |
| `issuer_did` | (no constant) | DIDMethodFactory | validateConfiguredIssuerDid | Expected issuer DID |
| `requested_credential` | (no constant) | DIDMethodFactory | - | Credential config JSON |

## Shared Auth Notes (DIDMethodFactory)

| Key | Constant | Description |
|-----|----------|-------------|
| `did_method` | `SSISessionConstants.DID_METHOD` | Selected DID method (sov/web) |
| `ssi_endpoint` | `SSISessionConstants.SSI_ENDPOINT` | Agent endpoint URL |
| `ssi_bearer_token` | `SSISessionConstants.SSI_BEARER_TOKEN` | Primary token key |
| `ssi_token` | `SSISessionConstants.SSI_TOKEN` | Legacy token key (deprecated) |
| `bearer_token` | (deprecated string) | Legacy fallback (deprecated) |
| `proof_request_json` | `SSISessionConstants.PROOF_REQUEST_JSON` | Proof request config JSON |
| `requested_credential` | (no constant) | Credential filter config |
| `subject_did` | (no constant) | Subject DID validation |
| `issuer_did` | (no constant) | Issuer DID validation |

## Verification

All auth note keys should use constants from `SSISessionConstants` class.
Legacy fallbacks (`bearer_token`, `ssi_token`) are marked `@Deprecated` but preserved for backward compatibility.
