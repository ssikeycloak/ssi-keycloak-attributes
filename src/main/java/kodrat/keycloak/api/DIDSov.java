package kodrat.keycloak.api;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;
import kodrat.keycloak.config.AttributeUtil;
import kodrat.keycloak.config.ConfigUtils;
import kodrat.keycloak.constant.SSIStatus;
import kodrat.keycloak.util.LogSanitizer;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.dto.did.ConnectionsResponse;
import kodrat.keycloak.dto.did.CreateInvitationResponse;
import kodrat.keycloak.dto.did.DIDSovConnection;
import kodrat.keycloak.dto.did.DIDSovProofResponse;
import kodrat.keycloak.service.HttpClientService;
import kodrat.keycloak.service.PollingService;
import kodrat.keycloak.service.QRCodeService;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import kodrat.keycloak.util.SSIErrorPageRenderer;

/**
 * Implementation of DIDMethod for did:sov (Sovrin framework).
 * Handles connection establishment, proof requests, and presentation verification
 * using the Sovrin DIDComm protocol.
 */
public class DIDSov implements DIDMethod {
    private static final Logger LOGGER = Logger.getLogger(DIDSov.class.getName());

    private static final ObjectMapper mapper = new ObjectMapper();

    private final String endpoint;

    private final String bearerToken;

    private final HttpClientService httpClientService;

    /**
     * Constructs a DIDSov instance with the specified endpoint and bearer token.
     *
     * @param endpoint The SSI agent endpoint URL
     * @param bearerToken The bearer token for authentication
     */
    public DIDSov(String endpoint, String bearerToken) {
        this.endpoint = endpoint;
        this.bearerToken = bearerToken;
        this.httpClientService = new HttpClientService(bearerToken);
    }

    /**
     * Handles the authentication flow for DID Sovrin.
     * Creates connection invitation, generates QR code, and displays authentication form.
     *
     * @param context The authentication flow context
     */
    public void handleAuthentication(AuthenticationFlowContext context) {
        LOGGER.info("[DIDSov] ====== HANDLE AUTHENTICATION START ======");
        LOGGER.info("[DIDSov] User: " + (context.getUser() != null ? LogSanitizer.maskIdentifier(context.getUser().getUsername()) : "NULL"));
        LOGGER.info("[DIDSov] Session ID: " + LogSanitizer.maskIdentifier(context.getAuthenticationSession().getParentSession().getId()));
        
        AuthenticationSessionModel session = context.getAuthenticationSession();
        String invitationUrl = session.getAuthNote(SSISessionConstants.INVITATION_URL);
        String msgId = session.getAuthNote(SSISessionConstants.INVI_MSG_ID);
        String tabId = session.getTabId();

        session.setAuthNote(SSISessionConstants.SSI_ENDPOINT, this.endpoint);
        session.setAuthNote(SSISessionConstants.SSI_BEARER_TOKEN, this.bearerToken);

        String existingConnectionId = getExistingConnectionIdByAlias(context);
        if (existingConnectionId != null) {
            LOGGER.info("[DIDSov] Reusing existing connection: " + LogSanitizer.maskIdentifier(existingConnectionId));
            session.setAuthNote(SSISessionConstants.CONNECTION_ID, existingConnectionId);
            session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.CONNECTED.getValue());
            String sessionId = session.getParentSession().getId();
            SSIResult proofResult = sendProofRequest(context);
            if (!proofResult.isDone()) {
                LOGGER.warning("[DIDSov] Failed to initiate proof request for existing connection");
                SSIErrorPageRenderer.render(context,
                        "SSI proof request failed",
                        "The SSI service could not start proof verification. You can continue login without SSI verification.");
                return;
            }
            context.challenge(context
                    .form()
                    .setAttribute("qrCode", "")
                    .setAttribute("sessionId", sessionId)
                    .setAttribute("tabId", tabId)
                    .createForm("login-auth-verify.ftl"));
            return;
        }
        if (invitationUrl == null || msgId == null) {
            LOGGER.info("[DIDSov] Creating new DIDComm invitation");
            try {
                CreateInvitationResponse invitation = createInvitation();
                if (invitation == null) {
                    LOGGER.warning("[DIDSov] Failed to create invitation via SSI agent");
                    SSIErrorPageRenderer.render(context,
                            "SSI connection failed",
                            "The SSI service could not generate a wallet invitation. You can continue login without SSI verification.");
                    return;
                }
                invitationUrl = invitation.getInvitationUrl();
                msgId = invitation.getInviMsgId();
                session.setAuthNote(SSISessionConstants.INVITATION_URL, invitationUrl);
                session.setAuthNote(SSISessionConstants.INVI_MSG_ID, msgId);
                session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.WAITING.getValue());
                LOGGER.info("[DIDSov] Invitation created and saved to session");
            } catch (Exception e) {
                LOGGER.severe("[DIDSov] Exception during invitation creation: " + LogSanitizer.redact(e.getMessage()));
                SSIErrorPageRenderer.render(context,
                        "SSI connection failed",
                        "The SSI service failed while preparing wallet verification. You can continue login without SSI verification.");
                return;
            }
        } else {
            LOGGER.info("[DIDSov] Reusing invitation from session");
        }
        String qrCodeUrl = QRCodeService.generateQRCodeUrl(invitationUrl);
        String sessionId = session.getParentSession().getId();
        long qrShownAtMs = System.currentTimeMillis();
        session.setAuthNote(SSISessionConstants.OOB_QR_SHOWN_AT, String.valueOf(qrShownAtMs));
        session.removeAuthNote(SSISessionConstants.OOB_QR_SCANNED_AT);
        session.removeAuthNote(SSISessionConstants.SOV_ACCEPT_CONN_ID);
        session.removeAuthNote(SSISessionConstants.SOV_ACCEPT_LAST_AT);
        session.removeAuthNote(SSISessionConstants.SOV_ACCEPTED_CONN_ID);
        LOGGER.info("[DIDSov] OOB QR displayed to user. invitation_msg_id=" + LogSanitizer.maskIdentifier(msgId)
                + ", shown_at=" + Instant.ofEpochMilli(qrShownAtMs));
        java.util.List<String> requestedAttributes = ConfigUtils.getRequestedAttributes(context);
        String schemaId = ConfigUtils.getSchemaId(context);
        String schemaName = ConfigUtils.getSchemaName(context);
        String issuerName = ConfigUtils.getIssuerName(context);
        String issuerDid = ConfigUtils.getIssuerDid(context);
        String uiConsentTitle = ConfigUtils.getUiConsentTitle(context);
        String uiConsentDescription = ConfigUtils.getUiConsentDescription(context);
        String uiRequiredDataTitle = ConfigUtils.getUiRequiredDataTitle(context);
        String uiPrivacyTitle = ConfigUtils.getUiPrivacyTitle(context);
        String uiPrivacyDescription = ConfigUtils.getUiPrivacyDescription(context);
        context.form().setAttribute("qrCode", qrCodeUrl);
        context.form().setAttribute("sessionId", sessionId);
        context.form().setAttribute("tabId", tabId);
        context.form().setAttribute("requestedAttributes", requestedAttributes);
        context.form().setAttribute("schemaId", schemaId);
        context.form().setAttribute("schemaName", schemaName);
        context.form().setAttribute("issuerName", issuerName);
        context.form().setAttribute("issuerDid", issuerDid);
        context.form().setAttribute("didMethod", "sov");
        context.form().setAttribute("methodDisplay", "Sovrin (did:sov)");
        context.form().setAttribute("protocolDisplay", "DIDComm/ACA-Py");
        context.form().setAttribute("uiConsentTitle", uiConsentTitle);
        context.form().setAttribute("uiConsentDescription", uiConsentDescription);
        context.form().setAttribute("uiRequiredDataTitle", uiRequiredDataTitle);
        context.form().setAttribute("uiPrivacyTitle", uiPrivacyTitle);
        context.form().setAttribute("uiPrivacyDescription", uiPrivacyDescription);

        LOGGER.info("[DIDSov] Displaying QR code for wallet connection");
        context.challenge(context.form().createForm("login-identity-consent.ftl"));
    }

    /**
     * Checks if a DID connection has been established.
     * Polls for active connection based on invitation message ID.
     *
     * @param context The authentication flow context
     * @return true if connection is established, false otherwise
     */
    public boolean isConnectionEstablished(AuthenticationFlowContext context) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        try {
            String existingConnectionId = getExistingConnectionIdByAlias(context);
            if (existingConnectionId != null) {
                LOGGER.info("[DIDSov] Existing connection found: " + LogSanitizer.maskIdentifier(existingConnectionId));
                session.setAuthNote(SSISessionConstants.CONNECTION_ID, existingConnectionId);
                session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.CONNECTED.getValue());
                return true;
            }
            String msgId = session.getAuthNote(SSISessionConstants.INVI_MSG_ID);
            if (msgId == null) {
                LOGGER.warning("[DIDSov] Invitation message ID not found in session");
                return false;
            }

            Long qrShownAtMs = parseEpochMillis(session.getAuthNote(SSISessionConstants.OOB_QR_SHOWN_AT));
            LOGGER.info("[DIDSov] Polling for active DIDComm connection");
            String connectionId = waitForActiveConnection(session, msgId, qrShownAtMs);
            if (connectionId == null) {
                LOGGER.warning("[DIDSov] No active connection established");
                return false;
            }

            if (qrShownAtMs != null) {
                long elapsedMs = System.currentTimeMillis() - qrShownAtMs;
                LOGGER.info("[DIDSov] Connection active after QR shown in " + elapsedMs + " ms");
            }
            session.setAuthNote(SSISessionConstants.CONNECTION_ID, connectionId);
            session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.CONNECTED.getValue());
            AuthenticationSessionModel authSession = context.getAuthenticationSession();
            boolean mapped = mapConnectionIdToUserAttribute(context, authSession);
            if (mapped) {
                LOGGER.info("[DIDSov] Connection mapped to user attributes");
            } else {
                LOGGER.warning("[DIDSov] Failed to persist connection to user attributes");
            }
            return true;
        } catch (Exception e) {
            LOGGER.severe("[DIDSov] Error establishing connection: " + LogSanitizer.redact(e.getMessage()));
            return false;
        }
    }

    /**
     * Checks if a connection is established via REST API.
     * Polls for active connection based on invitation message ID.
     *
     * @param session The authentication session model
     * @return true if connection is established, false otherwise
     */
    public boolean isConnectionEstablishedRestApi(AuthenticationSessionModel session) {
        try {
            String connection_id = session.getAuthNote(SSISessionConstants.CONNECTION_ID);

            LOGGER.fine("[DIDSov] [REST API] Checking connection status");

            if (connection_id != null && !connection_id.trim().isEmpty()) {
                LOGGER.info("[DIDSov] [REST API] Connection already established: " + LogSanitizer.maskIdentifier(connection_id));
                return true;
            }

            String msgId = session.getAuthNote(SSISessionConstants.INVI_MSG_ID);
            if (msgId == null) {
                LOGGER.warning("[DIDSov] [REST API] Invitation message ID not found");
                return false;
            }

            Long qrShownAtMs = parseEpochMillis(session.getAuthNote(SSISessionConstants.OOB_QR_SHOWN_AT));

            LOGGER.info("[DIDSov] [REST API] Probing DIDComm connection state");
            String connectionId = probeActiveConnectionOnce(session, msgId, qrShownAtMs);
            if (connectionId == null) {
                LOGGER.warning("[DIDSov] [REST API] No active connection found");
                return false;
            }

            if (qrShownAtMs != null) {
                long elapsedMs = System.currentTimeMillis() - qrShownAtMs;
                LOGGER.info("[DIDSov] [REST API] Connection active after QR shown in " + elapsedMs + " ms");
            }

            session.setAuthNote(SSISessionConstants.CONNECTION_ID, connectionId);
            session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.CONNECTED.getValue());

            return true;
        } catch (Exception e) {
            LOGGER.severe("[DIDSov] [REST API] Error checking connection: " + LogSanitizer.redact(e.getMessage()));
            return false;
        }
    }

    private String probeActiveConnectionOnce(AuthenticationSessionModel session, String msgId, Long qrShownAtMs) {
        String url = this.endpoint + "/connections";
        try {
            LOGGER.info("[INFO] [probeActiveConnectionOnce] GET " + url);
            ConnectionsResponse response = httpClientService.get(url, null, ConnectionsResponse.class);
            if (response.getResults() == null) {
                return null;
            }

            for (DIDSovConnection conn : response.getResults()) {
                String connId = conn.getConnectionId();
                String invitationMsgId = conn.getInvitationMsgId();
                if (!msgId.equals(invitationMsgId)) {
                    continue;
                }

                if (conn.isRequest()) {
                    markScanIfNeeded(session, qrShownAtMs);
                    maybeAcceptConnection(session, connId);
                }

                if (conn.isActive()) {
                    if (qrShownAtMs != null) {
                        LOGGER.info("[DIDSov] Wallet connection reached ACTIVE after "
                                + (System.currentTimeMillis() - qrShownAtMs) + " ms");
                    } else {
                        LOGGER.info("[DIDSov] Wallet connection reached ACTIVE");
                    }
                    LOGGER.info("[INFO] Active connection found: " + LogSanitizer.maskIdentifier(connId));
                    return connId;
                }
            }

            return null;
        } catch (Exception e) {
            LOGGER.warning("[WARNING] [probeActiveConnectionOnce] Exception: " + LogSanitizer.redact(e.getMessage()));
            return null;
        }
    }

    /**
     * Sends a proof request for credential verification.
     * Creates and sends a present-proof request using the established connection.
     *
     * @param context The authentication flow context
     * @return An SSIResult containing the presentation exchange ID
     */
    public SSIResult sendProofRequest(AuthenticationFlowContext context) {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        String connectionId = session.getAuthNote(SSISessionConstants.CONNECTION_ID);
        String presExId = session.getAuthNote(SSISessionConstants.PRES_EX_ID);
        if (presExId != null) {
            LOGGER.info("[DIDSov] Proof request already initiated: " + presExId);
            return new SSIResult(true, presExId, connectionId, Map.of("step", "already-requested"), "Already requested");
        }
        if (connectionId == null) {
            LOGGER.warning("[DIDSov] Connection ID not found in session");
            return SSIResult.notReady("Connection not available.");
        }
        try {
            LOGGER.info("[DIDSov] Sending proof request via DIDComm");
            String newPresExId = sendProofRequestInternal(context, connectionId);
            if (newPresExId == null) {
                LOGGER.warning("[DIDSov] Failed to send proof request to agent");
                return SSIResult.notReady("Failed to send proof request.");
            }
            session.setAuthNote(SSISessionConstants.PRES_EX_ID, newPresExId);
            session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.VERIFYING.getValue());
            LOGGER.info("[DIDSov] Proof request sent: " + newPresExId);
            Map<String, Object> extra = new HashMap<>();
            extra.put("step", "proof-requested");
            extra.put("connectionId", connectionId);
            return new SSIResult(true, newPresExId, connectionId, extra, "Proof request sent");
        } catch (Exception e) {
            LOGGER.severe("[DIDSov] Exception during proof request: " + LogSanitizer.redact(e.getMessage()));
            return SSIResult.notReady("Exception: " + e.getMessage());
        }
    }

    /**
     * Checks if a presentation has been received.
     * Queries the presentation exchange record to check state.
     *
     * @param context The authentication flow context
     * @return true if presentation received, false otherwise
     */
    public boolean hasReceivedPresentation(AuthenticationFlowContext context) {
        String presExId = context.getAuthenticationSession().getAuthNote(SSISessionConstants.PRES_EX_ID);
        if (presExId == null)
            return false;
        try {
            String url = this.endpoint + "/present-proof-2.0/records/" + presExId;
            DIDSovProofResponse response = httpClientService.get(url, null, DIDSovProofResponse.class);
            boolean received = response.isPresentationReceived();
            if (received) {
                LOGGER.info("[DIDSov] Presentation received from wallet");
            }
            return received;
        } catch (Exception e) {
            LOGGER.severe("[DIDSov] Error checking presentation status: " + LogSanitizer.redact(e.getMessage()));
            return false;
        }
    }

    /**
     * Checks if a presentation has been received via REST API.
     * Queries the presentation exchange record to check state.
     *
     * @param session The authentication session model
     * @return true if presentation received, false otherwise
     */
    public boolean hasReceivedPresentationRestApi(AuthenticationSessionModel session) {
        String presExId = session.getAuthNote(SSISessionConstants.PRES_EX_ID);
        if (presExId == null)
            return false;
        try {
            String url = this.endpoint + "/present-proof-2.0/records/" + presExId;
            DIDSovProofResponse response = httpClientService.get(url, null, DIDSovProofResponse.class);
            boolean received = response.isPresentationReceived();
            if (received) {
                LOGGER.info("[DIDSov] [REST API] Presentation received from wallet");
            }
            return received;
        } catch (Exception e) {
            LOGGER.severe("[DIDSov] [REST API] Error checking presentation: " + LogSanitizer.redact(e.getMessage()));
            return false;
        }
    }

    /**
     * Verifies the presentation via REST API.
     * Submits the presentation for verification and extracts revealed attributes.
     *
     * @param session The authentication session model
     * @return true if verification succeeds, false otherwise
     */
    public boolean verifyPresentationRestApi(AuthenticationSessionModel session) {
        String presExId = session.getAuthNote(SSISessionConstants.PRES_EX_ID);
        if (presExId == null) {
            LOGGER.warning("[DIDSov] [REST API] Presentation exchange ID not found");
            return false;
        }
        try {
            LOGGER.info("[DIDSov] [REST API] Verifying presentation: " + presExId);
            String url = this.endpoint + "/present-proof-2.0/records/" + presExId + "/verify-presentation";
            DIDSovProofResponse response = httpClientService.post(url, "{}", null, DIDSovProofResponse.class);
            LOGGER.fine("[DIDSov] [REST API] Agent response - State: " + response.getState() + ", Verified: " + response.getVerified());

            if (response.isVerified()) {
                Map<String, String> revealed = response.getRevealedAttributes();
                Map<String, String> mappedRevealed = mapReferentsToAttributeNames(session, revealed);
                List<Map<String, Object>> evidenceList = buildEvidenceFromSovrinResponse(response);
                LOGGER.info("[DIDSov] [REST API] Verification successful - " + mappedRevealed.size() + " attributes revealed");
                LOGGER.fine("[DIDSov] [REST API] Attributes: " + mappedRevealed.keySet());
                AttributeUtil.saveToUserSessionNote(session, mappedRevealed, evidenceList);
                LOGGER.info("[DIDSov] [REST API] Verification data saved to session");
                return true;
            } else {
                LOGGER.warning("[DIDSov] [REST API] Verification failed - State: " + response.getState());
            }
        } catch (Exception e) {
            LOGGER.severe("[DIDSov] [REST API] Exception during verification: " + LogSanitizer.redact(e.getMessage()));
        }
        return false;
    }

    /**
     * Verifies the presentation.
     * Submits the presentation for verification and extracts revealed attributes.
     *
     * @param context The authentication flow context
     * @return true if verification succeeds, false otherwise
     */
    public boolean verifyPresentation(AuthenticationFlowContext context) {
        String presExId = context.getAuthenticationSession().getAuthNote(SSISessionConstants.PRES_EX_ID);
        if (presExId == null) {
            LOGGER.warning("[DIDSov] Presentation exchange ID not found in session");
            return false;
        }
        try {
            LOGGER.info("[DIDSov] Verifying presentation: " + presExId);
            String url = this.endpoint + "/present-proof-2.0/records/" + presExId + "/verify-presentation";
            DIDSovProofResponse response = httpClientService.post(url, "{}", null, DIDSovProofResponse.class);
            LOGGER.fine("[DIDSov] Agent response - State: " + response.getState() + ", Verified: " + response.getVerified());
            if (response.isVerified()) {
                Map<String, String> revealed = response.getRevealedAttributes();
                Map<String, String> mappedRevealed = mapReferentsToAttributeNames(context.getAuthenticationSession(), revealed);
                List<Map<String, Object>> evidenceList = buildEvidenceFromSovrinResponse(response);
                LOGGER.info("[DIDSov] Verification successful - " + mappedRevealed.size() + " attributes revealed");
                LOGGER.fine("[DIDSov] Attributes: " + mappedRevealed.keySet());
                AttributeUtil.saveToUserSessionNote(context, mappedRevealed, evidenceList);
                LOGGER.info("[DIDSov] Verification data saved to session");
                return true;
            } else {
                LOGGER.warning("[DIDSov] Verification failed - State: " + response.getState());
            }
        } catch (Exception e) {
            LOGGER.severe("[DIDSov] Exception during verification: " + LogSanitizer.redact(e.getMessage()));
        }
        return false;
    }

    /**
     * Maps a connection ID to a user attribute for persistence.
     * Stores the connection ID in the user's ssiConnection attribute.
     *
     * @param context The authentication flow context
     * @param session The authentication session model
     * @return true if mapping succeeds, false otherwise
     */
    public static boolean mapConnectionIdToUserAttribute(AuthenticationFlowContext context, AuthenticationSessionModel session) {
        try {
            ObjectNode rootNode;
            UserModel user = context.getUser();
            if (user == null) {
                LOGGER.warning("Cannot map connection ID: user is null");
                return false;
            }
            String alias = null;
            if (context.getAuthenticatorConfig() != null && context.getAuthenticatorConfig().getAlias() != null) {
                alias = context.getAuthenticatorConfig().getAlias();
            } else {
                alias = "ssi";
            }
            String connectionId = session.getAuthNote(SSISessionConstants.CONNECTION_ID);
            if (connectionId == null) {
                LOGGER.warning("No connection_id in auth note.");
                return false;
            }
            String ssiRaw = user.getFirstAttribute("ssiConnection");
            if (ssiRaw != null && !ssiRaw.isEmpty()) {
                JsonNode parsedNode = mapper.readTree(ssiRaw);
                rootNode = (parsedNode instanceof ObjectNode) ? (ObjectNode)parsedNode : mapper.createObjectNode();
            } else {
                rootNode = mapper.createObjectNode();
            }
            ObjectNode connectionsNode = rootNode.has("connections") ? (ObjectNode)rootNode.get("connections") : mapper.createObjectNode();
            ObjectNode aliasNode = mapper.createObjectNode();
            aliasNode.put("connection_id", connectionId);
            aliasNode.put("last_used", Instant.now().toString());
            connectionsNode.set(alias, (JsonNode)aliasNode);
            rootNode.set("connections", (JsonNode)connectionsNode);
            user.setSingleAttribute("ssiConnection", mapper.writeValueAsString(rootNode));
            LOGGER.info("Connection ID successfully mapped to modul alias: " + alias);
            return true;
        } catch (Exception e) {
            LOGGER.severe("Failed to map connection ID: " + LogSanitizer.redact(e.getMessage()));
            return false;
        }
    }

    /**
     * Retrieves an existing connection ID from user attributes.
     * Looks up the connection ID stored for a specific alias.
     *
     * @param context The authentication flow context
     * @return The connection ID if found, null otherwise
     */
    public static String getExistingConnectionIdByAlias(AuthenticationFlowContext context) {
        try {
            UserModel user = context.getUser();
            if (user == null) {
                LOGGER.warning("Cannot read existing connection: user is null");
                return null;
            }
            String alias = null;
            if (context.getAuthenticatorConfig() != null && context.getAuthenticatorConfig().getAlias() != null) {
                alias = context.getAuthenticatorConfig().getAlias();
            } else {
                alias = "ssi";
            }
            String ssiRaw = user.getFirstAttribute("ssiConnection");
            if (ssiRaw == null || ssiRaw.isEmpty()) {
                LOGGER.info("No 'ssi_connection' data in user.");
                return null;
            }
            JsonNode rootNode = mapper.readTree(ssiRaw);
            JsonNode connectionsNode = rootNode.get("connections");
            if (connectionsNode == null || !connectionsNode.has(alias)) {
                LOGGER.info("No connection found for alias: " + alias);
                return null;
            }
            JsonNode aliasNode = connectionsNode.get(alias);
            if (aliasNode.has("connection_id")) {
                String connectionId = aliasNode.get("connection_id").asText();
                LOGGER.info("Connection ID found for alias " + alias + ": " + connectionId);
                return connectionId;
            }
            LOGGER.warning("Field 'connection_id' not found for alias " + alias);
            return null;
        } catch (Exception e) {
            LOGGER.severe("Failed to read connection ID: " + LogSanitizer.redact(e.getMessage()));
            return null;
        }
    }

    /**
     * Parses revealed attributes from a verification response.
     * Extracts attribute values from the revealed_attrs node.
     *
     * @param verifyResponseNode The verification response as a JsonNode
     * @return A map of attribute names to their values
     */
    public static Map<String, String> parseRevealedAttributes(JsonNode verifyResponseNode) {
        Map<String, String> attributes = new HashMap<>();
        try {
            JsonNode revealedAttrsNode = verifyResponseNode.path("by_format").path("pres").path("indy").path("requested_proof").path("revealed_attrs");
            if (!revealedAttrsNode.isObject())
                throw new IllegalArgumentException("Invalid or missing revealed_attrs");
            revealedAttrsNode.fields().forEachRemaining(entry -> {
                String referent = (String)entry.getKey();
                String rawValue = ((JsonNode)entry.getValue()).path("raw").asText(null);
                if (rawValue != null)
                    attributes.put(referent, rawValue);
            });
        } catch (Exception e) {
            LOGGER.severe("Failed to parse revealed attributes: " + LogSanitizer.redact(e.getMessage()));
        }
        return attributes;
    }

    /**
     * Builds evidence data from a Sovrin verification response.
     * Creates evidence structure for audit trails from verification result.
     *
     * @param verifyResponseNode The verification response as a JsonNode
     * @return A list of evidence maps
     */
    public static List<Map<String, Object>> buildEvidenceFromSovrin(JsonNode verifyResponseNode) {
        List<Map<String, Object>> evidenceList = new ArrayList<>();
        try {
            JsonNode identifiers = verifyResponseNode.path("by_format").path("pres").path("indy").path("identifiers");
            if (!identifiers.isArray() || identifiers.size() == 0)
                throw new IllegalArgumentException("No identifiers found in response");
            JsonNode firstIdentifier = identifiers.get(0);
            String schemaId = firstIdentifier.path("schema_id").asText(null);
            String credDefId = firstIdentifier.path("cred_def_id").asText(null);
            String updatedAt = verifyResponseNode.path("updated_at").asText(null);
            String[] schemaParts = (schemaId != null) ? schemaId.split(":") : new String[0];
            String issuerName = (schemaParts.length > 0) ? schemaParts[0] : "unknown";
            Map<String, Object> evidenceItem = new HashMap<>();
            evidenceItem.put("type", "document");
            evidenceItem.put("method", "didcomm/present-proof");
            evidenceItem.put("time", updatedAt);
            Map<String, Object> docDetails = new HashMap<>();
            docDetails.put("type", "identity_card");
            Map<String, String> issuer = new HashMap<>();
            issuer.put("name", issuerName);
            issuer.put("country", "ID");
            docDetails.put("issuer", issuer);
            evidenceItem.put("document_details", docDetails);
            evidenceList.add(evidenceItem);
        } catch (Exception e) {
            LOGGER.severe("Failed to build evidence from Sovrin: " + LogSanitizer.redact(e.getMessage()));
        }
        return evidenceList;
    }

    /**
     * Builds evidence data from a DIDSovProofResponse.
     * Creates evidence structure for audit trails from verification result.
     *
     * @param response The DIDSovProofResponse object
     * @return A list of evidence maps
     */
    public static List<Map<String, Object>> buildEvidenceFromSovrinResponse(DIDSovProofResponse response) {
        List<Map<String, Object>> evidenceList = new ArrayList<>();
        try {
            // Get the first identifier from the verification response
            // This contains credential metadata including schema ID
            Optional<DIDSovProofResponse.Identifier> firstIdentifier = response.getFirstIdentifier();
            if (firstIdentifier.isEmpty()) {
                throw new IllegalArgumentException("No identifiers found in response");
            }
            String schemaId = firstIdentifier.get().getSchemaId();
            String updatedAt = response.getUpdatedAt();
            // Parse schema ID to extract issuer information
            // Sovrin schema IDs follow pattern: "did:sov:issuerDID:name:version"
            String[] schemaParts = (schemaId != null) ? schemaId.split(":") : new String[0];
            String issuerName = (schemaParts.length > 0) ? schemaParts[0] : "unknown";
            // Build evidence structure for audit trail
            Map<String, Object> evidenceItem = new HashMap<>();
            evidenceItem.put("type", "document");
            evidenceItem.put("method", "didcomm/present-proof");
            evidenceItem.put("time", updatedAt);
            Map<String, Object> docDetails = new HashMap<>();
            docDetails.put("type", "identity_card");
            Map<String, String> issuer = new HashMap<>();
            issuer.put("name", issuerName);
            issuer.put("country", "ID");
            docDetails.put("issuer", issuer);
            evidenceItem.put("document_details", docDetails);
            evidenceList.add(evidenceItem);
        } catch (Exception e) {
            LOGGER.severe("[ERROR] Failed to build evidence from Sovrin: " + LogSanitizer.redact(e.getMessage()));
        }
        return evidenceList;
    }

    /**
     * Checks if the presentation has been verified.
     * Queries the verification status of the presentation exchange.
     *
     * @param context The authentication flow context
     * @return true if verified, false otherwise
     */
    public boolean isVerified(AuthenticationFlowContext context) {
        try {
            String presExId = context.getAuthenticationSession().getAuthNote(SSISessionConstants.PRES_EX_ID);
            if (presExId == null)
                return false;
            return checkVerification(presExId);
        } catch (Exception e) {
            LOGGER.severe("Failed in isVerified(): " + LogSanitizer.redact(e.getMessage()));
            return false;
        }
    }

    /**
     * Generates a QR code URL for the invitation.
     *
     * @param invitationUrl The invitation URL to encode
     * @return The QR code image URL
     */
    public String generateQRCode(String invitationUrl) {
        return QRCodeService.generateQRCodeUrl(invitationUrl);
    }

    /**
     * Creates a new DIDComm invitation for the wallet.
     *
     * <p>This method creates a new out-of-band invitation via the ACA-Py agent
     * and stores the invitation URL and message ID in the session. Used by REST API
     * when the existing invitation has been cleared (e.g., after retry).
     *
     * @param session the authentication session for storing invitation state
     * @return the invitation URL, or {@code null} if creation fails
     */
    @Override
    public String createInvitation(AuthenticationSessionModel session) {
        try {
            LOGGER.info("[DIDSov] Creating new invitation via REST API");
            CreateInvitationResponse invitation = createInvitation();
            if (invitation == null) {
                LOGGER.warning("[DIDSov] Failed to create invitation");
                return null;
            }
            String invitationUrl = invitation.getInvitationUrl();
            String msgId = invitation.getInviMsgId();
            session.setAuthNote(SSISessionConstants.INVITATION_URL, invitationUrl);
            session.setAuthNote(SSISessionConstants.INVI_MSG_ID, msgId);
            session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.WAITING.getValue());
            LOGGER.info("[DIDSov] Invitation created and saved to session");
            return invitationUrl;
        } catch (Exception e) {
            LOGGER.severe("[DIDSov] Exception creating invitation: " + LogSanitizer.redact(e.getMessage()));
            return null;
        }
    }

    private CreateInvitationResponse createInvitation() throws Exception {
        LOGGER.info("[DIDSov] ====== CREATE INVITATION START ======");
        LOGGER.info("[DIDSov] Endpoint: " + this.endpoint);
        
        ObjectNode payload = mapper.createObjectNode();
        payload.put("my_label", "Kodrat Login");
        payload.put("use_public_did", false);
        payload.set("accept", (JsonNode)mapper.createArrayNode().add("didcomm/aip1").add("didcomm/aip2;env=rfc19"));
        payload.set("handshake_protocols", (JsonNode)mapper.createArrayNode().add("https://didcomm.org/didexchange/1.0"));
        
        String url = this.endpoint + "/out-of-band/create-invitation";
        LOGGER.info("[DIDSov] Full URL: " + url);
        LOGGER.info("[DIDSov] Payload: " + LogSanitizer.redact(mapper.writeValueAsString(payload)));
        LOGGER.info("[DIDSov] Sending POST request to Aries agent...");
        
        long startTime = System.currentTimeMillis();
        CreateInvitationResponse response = httpClientService.post(url, payload, null, CreateInvitationResponse.class);
        long elapsed = System.currentTimeMillis() - startTime;
        
        LOGGER.info("[DIDSov] Response received in " + elapsed + "ms");
        LOGGER.info("[DIDSov] ====== CREATE INVITATION SUCCESS ======");
        return response;
    }

    private String waitForActiveConnection(AuthenticationSessionModel session, String msgId, Long qrShownAtMs) throws Exception {
        String url = this.endpoint + "/connections";

        // Poll the connections endpoint with retry logic
        // This waits for the mobile wallet to accept the connection invitation
        return PollingService.pollWithRetry(
            "waitForActiveConnection",
            () -> {
                try {
                    LOGGER.info("[INFO] [waitForActiveConnection] GET " + url);
                    ConnectionsResponse response = httpClientService.get(url, null, ConnectionsResponse.class);

                    // No connections yet, continue polling
                    if (response.getResults() == null) {
                        return Optional.empty();
                    }

                    // Iterate through all connections to find the one matching our invitation
                    for (DIDSovConnection conn : response.getResults()) {
                        String connId = conn.getConnectionId();
                        String state = conn.getState();
                        String rfc23 = conn.getRfc23State();
                        String invitationMsgId = conn.getInvitationMsgId();

                        // Skip connections that don't match our invitation
                        if (!msgId.equals(invitationMsgId))
                            continue;

                        // Connection is in "request" state - wallet has responded
                        // We need to accept the connection on our end to complete it
                        if (conn.isRequest()) {
                            markScanIfNeeded(session, qrShownAtMs);
                            maybeAcceptConnection(session, connId);
                        }

                        // Connection is active - ready for proof exchange
                        if (conn.isActive()) {
                            if (qrShownAtMs != null) {
                                LOGGER.info("[DIDSov] Wallet connection reached ACTIVE after "
                                        + (System.currentTimeMillis() - qrShownAtMs) + " ms");
                            } else {
                                LOGGER.info("[DIDSov] Wallet connection reached ACTIVE");
                            }
                            LOGGER.info("[INFO] Active connection found: " + LogSanitizer.maskIdentifier(connId));
                            return Optional.of(connId);
                        }
                    }
                    // No matching active connection found yet
                    return Optional.empty();
                } catch (Exception e) {
                    LOGGER.warning("[WARNING] [waitForActiveConnection] Exception: " + LogSanitizer.redact(e.getMessage()));
                    return Optional.empty();
                }
            },
            5,
            5000
        );
    }

    private boolean acceptConnection(String connId) throws Exception {
        String[] candidateUrls = new String[] {
                this.endpoint + "/didexchange/" + connId + "/accept-request",
                this.endpoint + "/api/acapy/didexchange/" + connId + "/accept-request",
                this.endpoint + "/connections/" + connId + "/accept-request"
        };

        String lastError = null;
        for (String url : candidateUrls) {
            LOGGER.info("[acceptConnection] POST " + url);
            try {
                httpClientService.post(url, "{}", null, String.class);
                LOGGER.info("[acceptConnection] Success via " + url);
                return true;
            } catch (Exception e) {
                String message = e.getMessage() == null ? "" : e.getMessage();
                lastError = message;
                boolean is404 = message.contains("404");
                LOGGER.warning("[acceptConnection] Endpoint failed: " + LogSanitizer.redact(message));
                if (!is404) {
                    return false;
                }
            }
        }

        LOGGER.warning("[acceptConnection] All endpoints failed" +
                (lastError != null ? ": " + LogSanitizer.redact(lastError) : ""));
        return false;
    }

    private void markScanIfNeeded(AuthenticationSessionModel session, Long qrShownAtMs) {
        if (session.getAuthNote(SSISessionConstants.OOB_QR_SCANNED_AT) != null) {
            return;
        }
        long scannedAtMs = System.currentTimeMillis();
        session.setAuthNote(SSISessionConstants.OOB_QR_SCANNED_AT, String.valueOf(scannedAtMs));
        if (qrShownAtMs != null) {
            LOGGER.info("[DIDSov] Wallet Bifold detected scan/accept (state=request) after "
                    + (scannedAtMs - qrShownAtMs) + " ms");
        } else {
            LOGGER.info("[DIDSov] Wallet Bifold detected scan/accept (state=request)");
        }
    }

    private void maybeAcceptConnection(AuthenticationSessionModel session, String connId) {
        String acceptedConnId = session.getAuthNote(SSISessionConstants.SOV_ACCEPTED_CONN_ID);
        if (connId.equals(acceptedConnId)) {
            LOGGER.fine("[DIDSov] Connection already accepted previously: " + LogSanitizer.maskIdentifier(connId));
            return;
        }

        long now = System.currentTimeMillis();
        String lastConnId = session.getAuthNote(SSISessionConstants.SOV_ACCEPT_CONN_ID);
        Long lastAttemptAt = parseEpochMillis(session.getAuthNote(SSISessionConstants.SOV_ACCEPT_LAST_AT));
        boolean sameConnRecentlyTried = connId.equals(lastConnId) && lastAttemptAt != null && (now - lastAttemptAt) < 4000;
        if (sameConnRecentlyTried) {
            LOGGER.fine("[DIDSov] Skipping duplicate accept attempt for connection: " + LogSanitizer.maskIdentifier(connId));
            return;
        }

        session.setAuthNote(SSISessionConstants.SOV_ACCEPT_CONN_ID, connId);
        session.setAuthNote(SSISessionConstants.SOV_ACCEPT_LAST_AT, String.valueOf(now));

        LOGGER.info("[INFO] Found request state, attempting to accept...");
        try {
            boolean accepted = acceptConnection(connId);
            if (accepted) {
                session.setAuthNote(SSISessionConstants.SOV_ACCEPTED_CONN_ID, connId);
            }
        } catch (Exception e) {
            LOGGER.warning("[DIDSov] Accept attempt failed: " + LogSanitizer.redact(e.getMessage()));
        }
    }

    private String sendProofRequestInternal(AuthenticationFlowContext context, String connectionId) throws Exception {
        // Get proof request configuration from Keycloak authenticator config
        JsonNode config = ConfigUtils.getProofRequestJson(context);
        if (config == null) {
            LOGGER.warning("[WARNING] [sendProofRequestInternal] Proof configuration is empty.");
            return null;
        }
        JsonNode attrs = config.get("attributes");
        JsonNode schemaIdNode = config.get("schemaId");
        if (attrs == null || schemaIdNode == null || !schemaIdNode.isTextual()) {
            LOGGER.warning("[WARNING] [sendProofRequestInternal] Attributes or schemaId are invalid.");
            return null;
        }
        // Build requested_attributes structure for Indy proof request format
        // Each attribute needs a unique referent name (attr1_referent, attr2_referent, etc.)
        ObjectNode requestedAttrs = mapper.createObjectNode();
        String schemaId = schemaIdNode.asText();
        int i = 1;
        for (JsonNode attr : attrs) {
            ObjectNode attrObj = mapper.createObjectNode();
            attrObj.put("name", attr.asText());
            // Restrict attributes to credentials with specific schema ID
            // This ensures only credentials from a trusted schema are accepted
            ObjectNode restriction = mapper.createObjectNode();
            restriction.put("schema_id", schemaId);
            attrObj.set("restrictions", (JsonNode)mapper.createArrayNode().add((JsonNode)restriction));
            requestedAttrs.set("attr" + i++ + "_referent", (JsonNode)attrObj);
        }
        // Build the Indy proof request structure
        ObjectNode indy = mapper.createObjectNode();
        indy.put("name", "Proof of Identity");
        indy.put("version", "1.0");
        indy.set("requested_attributes", (JsonNode)requestedAttrs);
        indy.set("requested_predicates", (JsonNode)mapper.createObjectNode());
        // Wrap proof request in the send-request payload
        ObjectNode payload = mapper.createObjectNode();
        payload.put("connection_id", connectionId);
        payload.set("presentation_request", mapper.createObjectNode().set("indy", (JsonNode)indy));
        payload.put("comment", "Requesting proof");
        payload.put("trace", false);
        payload.put("auto_remove", true);
        String url = this.endpoint + "/present-proof-2.0/send-request";
        LOGGER.info("[INFO] [sendProofRequestInternal] POST " + url);

        // Send proof request to the agent
        JsonNode response = httpClientService.post(url, payload, null, JsonNode.class);
        String presExId = response.path("pres_ex_id").asText(null);

        if (presExId != null) {
            LOGGER.info("[INFO] [sendProofRequestInternal] pres_ex_id: " + LogSanitizer.maskIdentifier(presExId));
        } else {
            LOGGER.warning("[WARNING] [sendProofRequestInternal] Failed to send proof request.");
        }
        return presExId;
    }

    private boolean checkVerification(String presExId) throws Exception {
        String url = this.endpoint + "/present-proof-2.0/records/" + presExId;
        LOGGER.info("[checkVerification] GET " + url);
        DIDSovProofResponse response = httpClientService.get(url, null, DIDSovProofResponse.class);
        LOGGER.info("[checkVerification] Current state: " + response.getState());
        return response.isVerifiedState();
    }

    private Long parseEpochMillis(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (Exception e) {
            LOGGER.warning("[DIDSov] Failed to parse epoch millis value: " + LogSanitizer.redact(value));
            return null;
        }
    }

    // ==== Session-based implementations for unified flow orchestration ====

    /**
     * Sends a proof request using session-based approach.
     * This implementation extracts configuration from session and sends proof request.
     */
    @Override
    public SSIResult sendProofRequest(AuthenticationSessionModel session) {
        String connectionId = session.getAuthNote(SSISessionConstants.CONNECTION_ID);
        String presExId = session.getAuthNote(SSISessionConstants.PRES_EX_ID);

        if (presExId != null) {
            LOGGER.info("[DIDSov] Proof request already initiated: " + LogSanitizer.maskIdentifier(presExId));
            return new SSIResult(true, presExId, connectionId, Map.of("step", "already-requested"), "Already requested");
        }

        if (connectionId == null) {
            LOGGER.warning("[DIDSov] Connection ID not found in session");
            return SSIResult.notReady("Connection not available.");
        }

        try {
            LOGGER.info("[DIDSov] Sending proof request via DIDComm (session-based)");
            String newPresExId = sendProofRequestInternal(session, connectionId);

            if (newPresExId == null) {
                LOGGER.warning("[DIDSov] Failed to send proof request to agent");
                return SSIResult.notReady("Failed to send proof request.");
            }

            session.setAuthNote(SSISessionConstants.PRES_EX_ID, newPresExId);
            session.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.VERIFYING.getValue());

            LOGGER.info("[DIDSov] Proof request sent: " + LogSanitizer.maskIdentifier(newPresExId));

            Map<String, Object> extra = new HashMap<>();
            extra.put("step", "proof-requested");
            extra.put("connectionId", connectionId);

            return new SSIResult(true, newPresExId, connectionId, extra, "Proof request sent");

        } catch (Exception e) {
            LOGGER.severe("[DIDSov] Exception during proof request: " + LogSanitizer.redact(e.getMessage()));
            return SSIResult.notReady("Exception: " + e.getMessage());
        }
    }

    private String sendProofRequestInternal(AuthenticationSessionModel session, String connectionId) throws Exception {
        String proofRequestJson = session.getAuthNote(SSISessionConstants.PROOF_REQUEST_JSON);
        String requestedCredentialJson = session.getAuthNote(SSISessionConstants.REQUESTED_CREDENTIAL);
        String schemaId = null;
        List<String> attributes = new ArrayList<>();

        if (proofRequestJson != null && !proofRequestJson.isEmpty()) {
            try {
                JsonNode jsonNode = mapper.readTree(proofRequestJson);
                schemaId = ConfigUtils.extractSchemaId(jsonNode);
            } catch (Exception e) {
                LOGGER.warning("[DIDSov] Failed to parse proof_request_json for schema_id: " + LogSanitizer.redact(e.getMessage()));
            }
            attributes.addAll(extractAttributesFromJson(proofRequestJson));
        }

        if (schemaId == null || schemaId.isEmpty()) {
            schemaId = ConfigUtils.extractSchemaId(requestedCredentialJson);
        }

        if (attributes.isEmpty()) {
            attributes.addAll(extractAttributesFromJson(requestedCredentialJson));
        }

        if (attributes.isEmpty() && schemaId != null && !schemaId.isEmpty()) {
            attributes.addAll(java.util.List.of("name", "NIK", "email", "phone"));
            LOGGER.info("[DIDSov] Using default tracking attributes as fallback (schema-matching enabled)");
        }

        if ((schemaId == null || schemaId.isEmpty()) && attributes.isEmpty()) {
            LOGGER.warning("[DIDSov] Proof configuration is empty - no schema_id or attributes");
            return null;
        }

        Map<String, Object> payload = new HashMap<>();
        payload.put("connection_id", connectionId);

        Map<String, Object> presentationRequest = new HashMap<>();
        presentationRequest.put("name", "Kodrat Login");
        presentationRequest.put("version", "1.0");
        presentationRequest.put("requested_predicates", new HashMap<>());

        Map<String, Object> requestedAttributes = new HashMap<>();
        Map<String, String> referentToAttrName = new HashMap<>();
        for (int i = 0; i < attributes.size(); i++) {
            String attrName = attributes.get(i);
            Map<String, Object> attrSpec = new HashMap<>();
            attrSpec.put("name", attrName);

            if (schemaId != null && !schemaId.isEmpty()) {
                attrSpec.put("restrictions", new ArrayList<>(List.of(new HashMap<>(Map.of("schema_id", schemaId)))));
            }

            String referent = "attr" + i + "_referent";
            requestedAttributes.put(referent, attrSpec);
            referentToAttrName.put(referent, attrName);
        }

        presentationRequest.put("requested_attributes", requestedAttributes);

        try {
            String mappingJson = mapper.writeValueAsString(referentToAttrName);
            session.setAuthNote("sov_referent_mapping", mappingJson);
            LOGGER.fine("[DIDSov] Saved referent mapping: " + mappingJson);
        } catch (Exception e) {
            LOGGER.warning("[DIDSov] Failed to save referent mapping: " + e.getMessage());
        }
        payload.put("presentation_request", Map.of("indy", presentationRequest));

        String url = this.endpoint + "/present-proof-2.0/send-request";
        LOGGER.info("[DIDSov] POST " + url);

        Map<String, Object> response = httpClientService.post(url, payload, null, Map.class);
        String presExId = (String) response.get("pres_ex_id");

        if (presExId != null) {
            LOGGER.info("[DIDSov] pres_ex_id received: " + LogSanitizer.maskIdentifier(presExId));
        } else {
            LOGGER.warning("[DIDSov] Failed to send proof request - no pres_ex_id in response");
        }

        return presExId;
    }

    /**
     * Verifies presentation using session-based approach.
     */
    @Override
    public boolean verifyPresentation(AuthenticationSessionModel session) {
        String presExId = session.getAuthNote(SSISessionConstants.PRES_EX_ID);

        if (presExId == null) {
            LOGGER.warning("[DIDSov] Presentation exchange ID not found in session");
            return false;
        }

        try {
            LOGGER.info("[DIDSov] Verifying presentation (session-based): " + LogSanitizer.maskIdentifier(presExId));

            // First check current state
            String url = this.endpoint + "/present-proof-2.0/records/" + presExId;
            DIDSovProofResponse response = httpClientService.get(url, null, DIDSovProofResponse.class);

            LOGGER.fine("[DIDSov] Current state: " + response.getState() + ", Verified: " + response.getVerified());

            // If not verified yet, trigger verification
            if (!response.isVerified() && "presentation-received".equalsIgnoreCase(response.getState())) {
                LOGGER.info("[DIDSov] Triggering verification for presentation");
                String verifyUrl = this.endpoint + "/present-proof-2.0/records/" + presExId + "/verify-presentation";
                response = httpClientService.post(verifyUrl, "{}", null, DIDSovProofResponse.class);
                LOGGER.fine("[DIDSov] Verification response - State: " + response.getState() + ", Verified: " + response.getVerified());
            }

            if (response.isVerified()) {
                Map<String, String> revealed = response.getRevealedAttributes();
                Map<String, String> mappedRevealed = mapReferentsToAttributeNames(session, revealed);
                List<Map<String, Object>> evidence = buildEvidenceFromSovrinResponse(response);

                AttributeUtil.saveToUserSessionNote(session, mappedRevealed, evidence);

                LOGGER.info("[DIDSov] Verification successful - " + mappedRevealed.size() + " attributes revealed");
                return true;
            } else {
                LOGGER.warning("[DIDSov] Verification failed - State: " + response.getState());
                return false;
            }
        } catch (Exception e) {
            LOGGER.severe("[DIDSov] Exception during verification: " + LogSanitizer.redact(e.getMessage()));
            return false;
        }
    }

    @Override
    public boolean isVerified(AuthenticationSessionModel session) {
        String presExId = session.getAuthNote(SSISessionConstants.PRES_EX_ID);
        if (presExId == null) {
            return false;
        }
        try {
            return checkVerification(presExId);
        } catch (Exception e) {
            LOGGER.severe("[DIDSov] Failed in isVerified(): " + LogSanitizer.redact(e.getMessage()));
            return false;
        }
    }

    @Override
    public boolean isConnectionEstablished(AuthenticationSessionModel session) {
        return isConnectionEstablishedRestApi(session);
    }

    @Override
    public boolean hasReceivedPresentation(AuthenticationSessionModel session) {
        return hasReceivedPresentationRestApi(session);
    }

    /**
     * Maps referent keys (e.g., "attr0_referent") to actual attribute names using the mapping stored in session.
     *
     * @param session The authentication session model
     * @param revealedAttrs The map with referent keys and their values
     * @return A map with attribute names as keys
     */
    private Map<String, String> mapReferentsToAttributeNames(AuthenticationSessionModel session, Map<String, String> revealedAttrs) {
        Map<String, String> result = new HashMap<>();
        if (revealedAttrs == null || revealedAttrs.isEmpty()) {
            return result;
        }

        // Try to load referent mapping from session
        String mappingJson = session.getAuthNote("sov_referent_mapping");
        Map<String, String> referentToAttrName = new HashMap<>();

        if (mappingJson != null && !mappingJson.isBlank()) {
            try {
                referentToAttrName = mapper.readValue(mappingJson, new TypeReference<Map<String, String>>() {});
                LOGGER.fine("[DIDSov] Loaded referent mapping: " + referentToAttrName);
            } catch (Exception e) {
                LOGGER.warning("[DIDSov] Failed to parse referent mapping, using referents as-is: " + e.getMessage());
            }
        }

        // Map each revealed attribute
        for (Map.Entry<String, String> entry : revealedAttrs.entrySet()) {
            String referent = entry.getKey();
            String value = entry.getValue();
            String attrName = referentToAttrName.getOrDefault(referent, referent);
            result.put(attrName, value);
        }

        return result;
    }

    private List<String> extractAttributesFromJson(String jsonString) {
        List<String> attributes = new ArrayList<>();
        if (jsonString == null || jsonString.isEmpty()) {
            return attributes;
        }
        try {
            JsonNode jsonNode = mapper.readTree(jsonString);
            if (jsonNode.has("attributes") && jsonNode.get("attributes").isArray()) {
                for (JsonNode attr : jsonNode.get("attributes")) {
                    String value = attr.asText();
                    if (value != null && !value.isBlank()) {
                        attributes.add(value);
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.warning("[DIDSov] Failed to parse JSON for attributes: " + LogSanitizer.redact(e.getMessage()));
        }
        return attributes;
    }
}
