package kodrat.keycloak.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import kodrat.keycloak.util.LogSanitizer;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.Logger;

/**
 * Utility service for extracting credential attributes from SSI verification responses.
 *
 * <p>This class handles the extraction of revealed attributes from verifiable credentials,
 * validates DID constraints (subject_did, issuer_did), and provides fallback extraction
 * for unknown credential types. It supports both DID Web (OpenID4VC) and DID Sov
 * (Indy/Aries) verification responses.
 *
 * <h2>Supported Credential Formats</h2>
 * <ul>
 *   <li><strong>W3C Verifiable Credentials:</strong> JWT-VC format used by did:web</li>
 *   <li><strong>Indy AnonCreds:</strong> Hyperledger Indy credential format used by did:sov</li>
 * </ul>
 *
 * <h2>DID Validation</h2>
 * <p>When configured, validates that:
 * <ul>
 *   <li><strong>subject_did:</strong> The credential subject DID matches the expected value</li>
 *   <li><strong>issuer_did:</strong> The credential issuer DID matches the expected value</li>
 * </ul>
 *
 * <h2>Attribute Extraction</h2>
 * <p>Attributes are extracted in the following order:
 * <ol>
 *   <li>Direct top-level fields in credential subject</li>
 *   <li>Nested fields using dot notation (e.g., "address.city")</li>
 *   <li>Fields within "achievement" object (for educational credentials)</li>
 *   <li>Fallback: All scalar fields up to specified depth</li>
 * </ol>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * JsonNode credentialSubject = response.getCredentialSubject();
 * JsonNode policyResults = responseNode.path("policyResults");
 * 
 * Map<String, String> attributes = CredentialAttributeExtractor.extractFromDidWeb(
 *     session,
 *     credentialSubject,
 *     policyResults,
 *     requestedCredentialJson
 * );
 * 
 * if (attributes != null) {
 *     // Attributes extracted successfully
 *     String name = attributes.get("name");
 * } else {
 *     // DID validation failed - check ssi_failure_reason session note
 * }
 * }</pre>
 *
 * <h2>Failure Reasons</h2>
 * <p>When extraction returns {@code null}, the failure reason is stored in the
 * {@code ssi_failure_reason} session note:
 * <ul>
 *   <li>{@code subject_id_missing} - Credential subject has no "id" field</li>
 *   <li>{@code subject_did_mismatch} - Subject DID doesn't match configured value</li>
 *   <li>{@code issuer_did_missing} - Issuer DID not found in credential</li>
 *   <li>{@code issuer_did_mismatch} - Issuer DID doesn't match configured value</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is stateless and all methods are static. It is safe to call from
 * multiple threads concurrently.
 *
 * @see EvidenceBuilder
 * @see AttributeUtil
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public final class CredentialAttributeExtractor {
    
    private static final Logger LOGGER = Logger.getLogger(CredentialAttributeExtractor.class.getName());
    
    private static final String FAILURE_REASON_NOTE = "ssi_failure_reason";
    
    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Private constructor to prevent instantiation.
     * This is a utility class with only static methods.
     */
    private CredentialAttributeExtractor() {}

    /**
     * Extracts credential attributes from a DID Web (OpenID4VC) verification response.
     *
     * <p>This method:
     * <ol>
     *   <li>Parses the requested attributes from configuration</li>
     *   <li>Validates subject_did and issuer_did constraints if configured</li>
     *   <li>Extracts requested attributes from credential subject</li>
     *   <li>Falls back to collecting all scalar fields if no matches found</li>
     * </ol>
     *
     * @param session the authentication session for reading configuration and
     *                storing failure reasons
     * @param credentialSubject the credential subject JSON node from the verification
     * @param policyResultsNode the policy results node for issuer DID extraction
     * @param requestedCredentialJson JSON specifying requested attributes and credential type
     * @return a map of attribute names to values; {@code null} if DID validation fails
     */
    public static Map<String, String> extractFromDidWeb(
            AuthenticationSessionModel session,
            JsonNode credentialSubject,
            JsonNode policyResultsNode,
            String requestedCredentialJson) {
        
        Map<String, String> revealedAttrs = new HashMap<>();
        Set<String> requestedAttributes = parseRequestedAttributes(requestedCredentialJson);

        String configuredSubjectDid = session.getAuthNote("subject_did");
        String configuredIssuerDid = session.getAuthNote("issuer_did");
        
        if (!validateDidConstraints(session, credentialSubject, policyResultsNode, configuredSubjectDid, configuredIssuerDid)) {
            return null;
        }

        Set<String> availableTopLevelKeys = collectTopLevelKeys(credentialSubject);

        for (String requestedAttr : requestedAttributes) {
            Optional<String> extractedValue = extractAttributeValue(credentialSubject, requestedAttr);
            extractedValue.ifPresent(value -> revealedAttrs.putIfAbsent(requestedAttr, value));
        }

        if (revealedAttrs.isEmpty() && !requestedAttributes.isEmpty()) {
            LOGGER.warning("[CredentialAttributeExtractor] No requested attributes matched: requested="
                    + requestedAttributes + ", available=" + availableTopLevelKeys);
            return revealedAttrs;
        }

        if (revealedAttrs.isEmpty()) {
            collectScalarCredentialFields(credentialSubject, "", revealedAttrs, 2);
            if (!revealedAttrs.isEmpty()) {
                LOGGER.info("[CredentialAttributeExtractor] Fallback extraction: " + revealedAttrs.keySet());
            }
        }

        return revealedAttrs;
    }

    /**
     * Extracts credential attributes using AuthenticationFlowContext.
     *
     * <p>Alternative entry point for authenticator-based flows where configuration
     * is accessed via the authenticator config rather than session notes.
     *
     * @param context the Keycloak authentication flow context
     * @param credentialSubject the credential subject JSON node
     * @param policyResultsNode the policy results node
     * @return a map of attribute names to values; {@code null} if validation fails
     */
    public static Map<String, String> extractFromDidWebContext(
            org.keycloak.authentication.AuthenticationFlowContext context,
            JsonNode credentialSubject,
            JsonNode policyResultsNode) {
        
        Map<String, String> revealedAttrs = new HashMap<>();
        Set<String> requestedAttributes = parseRequestedAttributesFromContext(context);

        String configuredSubjectDid = context.getAuthenticatorConfig().getConfig().get("subject_did");
        String configuredIssuerDid = context.getAuthenticatorConfig().getConfig().get("issuer_did");
        
        if (!validateDidConstraintsContext(context, credentialSubject, policyResultsNode, configuredSubjectDid, configuredIssuerDid)) {
            return null;
        }

        for (String requestedAttr : requestedAttributes) {
            Optional<String> extractedValue = extractAttributeValue(credentialSubject, requestedAttr);
            extractedValue.ifPresent(value -> revealedAttrs.putIfAbsent(requestedAttr, value));
        }

        if (revealedAttrs.isEmpty() && !requestedAttributes.isEmpty()) {
            collectScalarCredentialFields(credentialSubject, "", revealedAttrs, 2);
        }

        return revealedAttrs;
    }

    /**
     * Parses the requested attributes from a JSON configuration string.
     *
     * @param requestedCredentialJson the JSON string containing the attributes array
     * @return a set of requested attribute names; empty set if parsing fails
     */
    private static Set<String> parseRequestedAttributes(String requestedCredentialJson) {
        Set<String> requestedAttributes = new HashSet<>();
        String defaultJson = "{ \"credential_type\": \"VerifiableDiploma\", \"attributes\": [] }";
        String json = (requestedCredentialJson != null && !requestedCredentialJson.isBlank()) 
            ? requestedCredentialJson : defaultJson;

        try {
            JsonNode data = mapper.readTree(json);
            JsonNode attributes = data.path("attributes");
            if (attributes.isArray()) {
                for (JsonNode attr : attributes) {
                    requestedAttributes.add(attr.asText());
                }
            }
        } catch (Exception e) {
            LOGGER.fine("[CredentialAttributeExtractor] Failed to parse requested_credential JSON");
        }
        return requestedAttributes;
    }

    /**
     * Parses requested attributes from authenticator config.
     *
     * @param context the authentication flow context
     * @return a set of requested attribute names
     */
    private static Set<String> parseRequestedAttributesFromContext(org.keycloak.authentication.AuthenticationFlowContext context) {
        Set<String> requestedAttributes = new HashSet<>();
        Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        String defaultJson = "{ \"credential_type\": \"VerifiableDiploma\", \"attributes\": [] }";
        String json = config.getOrDefault("requested_credential", defaultJson);

        try {
            JsonNode data = mapper.readTree(json);
            JsonNode attributes = data.path("attributes");
            if (attributes.isArray()) {
                for (JsonNode attr : attributes) {
                    requestedAttributes.add(attr.asText());
                }
            }
        } catch (Exception e) {
            LOGGER.fine("[CredentialAttributeExtractor] Failed to parse requested_credential JSON");
        }
        return requestedAttributes;
    }

    /**
     * Validates DID constraints against the credential.
     *
     * @param session the authentication session
     * @param credentialSubject the credential subject node
     * @param policyResultsNode the policy results node
     * @param configuredSubjectDid the configured subject DID constraint
     * @param configuredIssuerDid the configured issuer DID constraint
     * @return {@code true} if validation passes, {@code false} otherwise
     */
    private static boolean validateDidConstraints(AuthenticationSessionModel session, JsonNode credentialSubject,
            JsonNode policyResultsNode, String configuredSubjectDid, String configuredIssuerDid) {
        
        boolean hasSubjectCheck = configuredSubjectDid != null && !configuredSubjectDid.isBlank();
        boolean hasIssuerCheck = configuredIssuerDid != null && !configuredIssuerDid.isBlank();

        if (hasSubjectCheck) {
            JsonNode subjectIdNode = credentialSubject.get("id");
            if (subjectIdNode == null || subjectIdNode.isNull()) {
                session.setAuthNote(FAILURE_REASON_NOTE, "subject_id_missing");
                return false;
            }
            String actualDid = subjectIdNode.asText();
            if (!normalizeDid(configuredSubjectDid).equals(normalizeDid(actualDid))) {
                logMismatch(session, configuredSubjectDid, actualDid, "subject");
                session.setAuthNote(FAILURE_REASON_NOTE, "subject_did_mismatch");
                return false;
            }
        } else if (hasIssuerCheck) {
            String actualDid = extractIssuerDidFromPolicyResults(policyResultsNode);
            if (actualDid == null || actualDid.isBlank()) {
                session.setAuthNote(FAILURE_REASON_NOTE, "issuer_did_missing");
                return false;
            }
            if (!normalizeDid(configuredIssuerDid).equals(normalizeDid(actualDid))) {
                logMismatch(session, configuredIssuerDid, actualDid, "issuer");
                session.setAuthNote(FAILURE_REASON_NOTE, "issuer_did_mismatch");
                return false;
            }
        }
        return true;
    }

    /**
     * Validates DID constraints using AuthenticationFlowContext.
     */
    private static boolean validateDidConstraintsContext(org.keycloak.authentication.AuthenticationFlowContext context,
            JsonNode credentialSubject, JsonNode policyResultsNode, String configuredSubjectDid, String configuredIssuerDid) {
        
        boolean hasSubjectCheck = configuredSubjectDid != null && !configuredSubjectDid.isBlank();
        boolean hasIssuerCheck = configuredIssuerDid != null && !configuredIssuerDid.isBlank();

        if (hasSubjectCheck) {
            JsonNode subjectIdNode = credentialSubject.get("id");
            if (subjectIdNode == null || subjectIdNode.isNull()) {
                context.getAuthenticationSession().setAuthNote(FAILURE_REASON_NOTE, "subject_id_missing");
                return false;
            }
            String actualDid = subjectIdNode.asText();
            if (!normalizeDid(configuredSubjectDid).equals(normalizeDid(actualDid))) {
                logMismatchContext(context, configuredSubjectDid, actualDid, "subject");
                context.getAuthenticationSession().setAuthNote(FAILURE_REASON_NOTE, "subject_did_mismatch");
                return false;
            }
        } else if (hasIssuerCheck) {
            String actualDid = extractIssuerDidFromPolicyResults(policyResultsNode);
            if (actualDid == null || actualDid.isBlank()) {
                context.getAuthenticationSession().setAuthNote(FAILURE_REASON_NOTE, "issuer_did_missing");
                return false;
            }
            if (!normalizeDid(configuredIssuerDid).equals(normalizeDid(actualDid))) {
                logMismatchContext(context, configuredIssuerDid, actualDid, "issuer");
                context.getAuthenticationSession().setAuthNote(FAILURE_REASON_NOTE, "issuer_did_mismatch");
                return false;
            }
        }
        return true;
    }

    /**
     * Logs a DID mismatch warning.
     */
    private static void logMismatch(AuthenticationSessionModel session, String expected, String actual, String type) {
        LOGGER.warning("[CredentialAttributeExtractor] " + type + "_did mismatch - expected=" + summarizeDid(expected)
                + ", actual=" + summarizeDid(actual));
    }

    /**
     * Logs a DID mismatch warning via context.
     */
    private static void logMismatchContext(org.keycloak.authentication.AuthenticationFlowContext context, 
            String expected, String actual, String type) {
        LOGGER.warning("[CredentialAttributeExtractor] " + type + "_did mismatch - expected=" + summarizeDid(expected)
                + ", actual=" + summarizeDid(actual));
    }

    /**
     * Collects all top-level keys from a JSON object.
     *
     * @param credentialSubject the JSON node to inspect
     * @return a set of field names
     */
    private static Set<String> collectTopLevelKeys(JsonNode credentialSubject) {
        Set<String> keys = new HashSet<>();
        Iterator<Map.Entry<String, JsonNode>> fields = credentialSubject.fields();
        while (fields.hasNext()) {
            keys.add(fields.next().getKey());
        }
        return keys;
    }

    /**
     * Extracts a single attribute value from credential subject.
     *
     * <p>Looks for the attribute in the following order:
     * <ol>
     *   <li>Direct top-level field</li>
     *   <li>Nested field using dot notation</li>
     *   <li>Field within "achievement" object</li>
     * </ol>
     *
     * @param credentialSubject the credential subject JSON node
     * @param requestedAttr the attribute name to extract
     * @return an Optional containing the value if found
     */
    public static Optional<String> extractAttributeValue(JsonNode credentialSubject, String requestedAttr) {
        if (requestedAttr == null || requestedAttr.isBlank()) {
            return Optional.empty();
        }

        JsonNode direct = credentialSubject.path(requestedAttr);
        if (!direct.isMissingNode() && !direct.isNull()) {
            return Optional.of(direct.isTextual() ? direct.asText() : direct.toString());
        }

        if (requestedAttr.contains(".")) {
            JsonNode nested = resolveNestedAttribute(credentialSubject, requestedAttr);
            if (!nested.isMissingNode() && !nested.isNull()) {
                return Optional.of(nested.isTextual() ? nested.asText() : nested.toString());
            }
        }

        JsonNode achievementField = credentialSubject.path("achievement").path(requestedAttr);
        if (!achievementField.isMissingNode() && !achievementField.isNull()) {
            return Optional.of(achievementField.isTextual() ? achievementField.asText() : achievementField.toString());
        }

        return Optional.empty();
    }

    /**
     * Resolves a nested attribute using dot notation path.
     *
     * @param root the root JSON node
     * @param pathExpression the dot-separated path (e.g., "address.city")
     * @return the resolved node, or missing node if not found
     */
    private static JsonNode resolveNestedAttribute(JsonNode root, String pathExpression) {
        if (!pathExpression.contains(".")) {
            return JsonNodeFactory.instance.missingNode();
        }
        JsonNode current = root;
        for (String part : pathExpression.split("\\.")) {
            current = current.path(part);
            if (current.isMissingNode()) {
                return current;
            }
        }
        return current;
    }

    /**
     * Recursively collects all scalar fields from a JSON node.
     *
     * <p>Used as fallback when no requested attributes are matched.
     *
     * @param node the JSON node to traverse
     * @param prefix the current path prefix
     * @param out the output map to collect values
     * @param depthLeft maximum recursion depth remaining
     */
    public static void collectScalarCredentialFields(JsonNode node, String prefix, Map<String, String> out, int depthLeft) {
        if (node == null || depthLeft < 0 || node.isNull()) {
            return;
        }
        if (node.isTextual() || node.isNumber() || node.isBoolean()) {
            if (!prefix.isBlank()) {
                out.putIfAbsent(prefix, node.asText());
            }
            return;
        }
        if (!node.isObject()) {
            return;
        }
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String nextPrefix = prefix.isBlank() ? entry.getKey() : prefix + "." + entry.getKey();
            collectScalarCredentialFields(entry.getValue(), nextPrefix, out, depthLeft - 1);
        }
    }

    /**
     * Extracts the issuer DID from policy results.
     *
     * <p>Navigates the policy results structure to find the issuer:
     * <pre>
     * policyResults.results[].policyResults[].result.vc.issuer
     * </pre>
     *
     * @param policyResultsNode the policy results JSON node
     * @return the issuer DID, or {@code null} if not found
     */
    public static String extractIssuerDidFromPolicyResults(JsonNode policyResultsNode) {
        if (policyResultsNode == null) {
            return null;
        }
        JsonNode resultsNode = policyResultsNode.path("results");
        if (!resultsNode.isArray()) {
            return null;
        }
        for (JsonNode result : resultsNode) {
            JsonNode policyArray = result.path("policyResults");
            if (!policyArray.isArray()) continue;
            for (JsonNode policy : policyArray) {
                JsonNode resultNode = policy.path("result");
                JsonNode vcNode = resultNode.path("vc");
                if (!vcNode.isMissingNode()) {
                    JsonNode issuerNode = vcNode.path("issuer");
                    if (issuerNode.isObject()) {
                        String issuerId = issuerNode.path("id").asText(null);
                        if (issuerId != null && !issuerId.isBlank()) {
                            return issuerId;
                        }
                    }
                    if (issuerNode.isTextual()) {
                        String issuerValue = issuerNode.asText();
                        if (!issuerValue.isBlank()) {
                            return issuerValue;
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Normalizes a DID by removing whitespace and zero-width characters.
     *
     * @param did the DID to normalize
     * @return the normalized DID, or {@code null} if input is null
     */
    private static String normalizeDid(String did) {
        if (did == null) return null;
        return did.strip().replace("\u200B", "").replace("\uFEFF", "");
    }

    /**
     * Creates a summarized representation of a DID for logging.
     *
     * @param did the DID to summarize
     * @return a masked representation with length info
     */
    private static String summarizeDid(String did) {
        if (did == null || did.isBlank()) return "[EMPTY]";
        return LogSanitizer.maskIdentifier(did) + " (len=" + did.length() + ")";
    }
}
