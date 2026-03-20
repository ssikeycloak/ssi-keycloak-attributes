package kodrat.keycloak.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.util.LogSanitizer;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Utility class for managing verified claims and credential attributes in Keycloak sessions.
 *
 * <p>This class handles the storage of extracted credential attributes in the OpenID4VC
 * verified_claims format, which combines identity claims with verification evidence.
 * The data is persisted to both authentication session notes and user session notes
 * for access by token mappers.
 *
 * <h2>Verified Claims Structure</h2>
 * <p>The verified_claims object follows the OpenID4VC specification:
 * <pre>{@code
 * {
 *   "verification": {
 *     "evidence": [
 *       {
 *         "type": "document",
 *         "method": "jwt_vp",
 *         "time": "2024-01-15T10:30:00Z",
 *         "document_details": {
 *           "type": "VerifiableDiploma",
 *           "issuer": {
 *             "name": "did:web:example.com"
 *           }
 *         }
 *       }
 *     ],
 *     "assurance_level": "high",
 *     "trust_framework": null
 *   },
 *   "claims": {
 *     "name": "John Doe",
 *     "email": "john@example.com",
 *     "NIK": "1234567890"
 *   }
 * }
 * }</pre>
 *
 * <h2>Storage Locations</h2>
 * <p>Verified claims are stored in two locations:
 * <ul>
 *   <li><strong>Auth Session Note:</strong> For access during the authentication flow</li>
 *   <li><strong>User Session Note:</strong> For access by token mappers (OIDC protocol mapper)</li>
 * </ul>
 *
 * <h2>Token Mapper Configuration</h2>
 * <p>To include verified claims in access tokens:
 * <ol>
 *   <li>Create a "User Session Note" protocol mapper in your client scope</li>
 *   <li>Set the session note property to "verified_claims"</li>
 *   <li>Set the token claim name to "verified_claims"</li>
 * </ol>
 *
 * <h2>Merge Behavior</h2>
 * <p>When saving attributes, the class merges with existing claims:
 * <ul>
 *   <li>New claims are added to the existing claims map</li>
 *   <li>Existing claims with the same key are overwritten</li>
 *   <li>Evidence items are appended to the existing evidence array</li>
 * </ul>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * // From authenticator context
 * Map<String, String> revealedAttrs = Map.of("name", "John", "email", "john@example.com");
 * List<Map<String, Object>> evidence = EvidenceBuilder.buildFromDidWeb(policyResults);
 * AttributeUtil.saveToUserSessionNote(context, revealedAttrs, evidence);
 *
 * // From REST API (session only)
 * AttributeUtil.saveToUserSessionNote(session, revealedAttrs, evidence);
 *
 * // Retrieve flattened attributes
 * Map<String, String> allAttrs = AttributeUtil.getFlattenedAttributes(session);
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is stateless and all methods are static. It is safe to call from
 * multiple threads concurrently. Session modifications are handled by Keycloak's
 * thread-safe session management.
 *
 * @see CredentialAttributeExtractor
 * @see EvidenceBuilder
 * @see SSISessionConstants#VERIFIED_CLAIMS
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class AttributeUtil {
    
    private static final Logger LOGGER = Logger.getLogger(AttributeUtil.class.getName());

    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Private constructor to prevent instantiation.
     * This is a utility class with only static methods.
     */
    private AttributeUtil() {}

    /**
     * Loads existing verified claims or initializes a new structure.
     *
     * <p>Looks for existing claims in:
     * <ol>
     *   <li>Authentication session auth notes</li>
     *   <li>User session notes</li>
     * </ol>
     *
     * <p>If not found, creates a new structure with empty claims and evidence.
     *
     * @param session the authentication session
     * @return a verified claims map with "verification" and "claims" keys
     * @throws Exception if JSON parsing fails
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadOrInitVerifiedClaims(AuthenticationSessionModel session) throws Exception {
        String existing = session.getAuthNote(SSISessionConstants.VERIFIED_CLAIMS);
        if (existing != null && !existing.isBlank()) {
            try {
                Map<String, Object> parsed = (Map<String, Object>) mapper.readValue(existing, new TypeReference<Map<String, Object>>() {
                });
                LOGGER.info("[AttributeUtil] merge-source=authNote, payloadLength=" + existing.length());
                return parsed;
            } catch (Exception e) {
                LOGGER.warning("[AttributeUtil] Failed to parse verified_claims from auth note, trying user session note");
            }
        }

        String fromUserSession = null;
        if (session.getUserSessionNotes() != null) {
            fromUserSession = session.getUserSessionNotes().get(SSISessionConstants.VERIFIED_CLAIMS);
        }

        if (fromUserSession != null && !fromUserSession.isBlank()) {
            try {
                Map<String, Object> parsed = (Map<String, Object>) mapper.readValue(fromUserSession, new TypeReference<Map<String, Object>>() {
                });
                LOGGER.info("[AttributeUtil] merge-source=userSessionNote, payloadLength=" + fromUserSession.length());
                return parsed;
            } catch (Exception e) {
                LOGGER.warning("[AttributeUtil] Failed to parse verified_claims from user session note, reinitializing");
            }
        }

        Map<String, Object> verifiedClaims = new HashMap<>();
        verifiedClaims.put("verification", new HashMap<>());
        verifiedClaims.put("claims", new HashMap<>());
        Map<String, Object> verification = (Map<String, Object>) verifiedClaims.get("verification");
        verification.put("evidence", new ArrayList<>());
        verification.put("assurance_level", "high");
        verification.put("trust_framework", null);
        LOGGER.info("[AttributeUtil] merge-source=init-new");
        return verifiedClaims;
    }

    /**
     * Saves extracted attributes and evidence to user session via AuthenticationFlowContext.
     *
     * <p>Merges the provided attributes and evidence with any existing verified claims,
     * then persists to both auth session and user session notes.
     *
     * @param context the Keycloak authentication flow context
     * @param revealedAttrs the extracted credential attributes
     * @param evidenceAttrs the verification evidence items
     */
    public static void saveToUserSessionNote(AuthenticationFlowContext context, Map<String, String> revealedAttrs, List<Map<String, Object>> evidenceAttrs) {
        try {
            AuthenticationSessionModel session = context.getAuthenticationSession();
            Map<String, Object> verifiedClaims = loadOrInitVerifiedClaims(session);

            Map<String, Object> existingClaims = (Map<String, Object>)verifiedClaims.get("claims");
            List<Map<String, Object>> existingEvidence = (List<Map<String, Object>>)((Map)verifiedClaims.get("verification")).get("evidence");
            int claimsBefore = existingClaims.size();
            int evidenceBefore = existingEvidence.size();

            LOGGER.info("[AttributeUtil] merge-start mode=flowContext incomingClaims=" + revealedAttrs.size() +
                    ", incomingEvidence=" + evidenceAttrs.size() +
                    ", existingClaims=" + claimsBefore +
                    ", existingEvidence=" + evidenceBefore);

            for (Map.Entry<String, String> entry : revealedAttrs.entrySet())
                existingClaims.put(entry.getKey(), entry.getValue());
            existingEvidence.addAll(evidenceAttrs);
            String json = mapper.writeValueAsString(verifiedClaims);

            LOGGER.info("[AttributeUtil] merge-end mode=flowContext totalClaims=" + existingClaims.size() +
                    ", totalEvidence=" + existingEvidence.size() +
                    ", claimKeys=" + existingClaims.keySet());

            session.setUserSessionNote(SSISessionConstants.VERIFIED_CLAIMS, json);
            session.setAuthNote(SSISessionConstants.VERIFIED_CLAIMS, json);

            LOGGER.info("[AttributeUtil] verified_claims saved (flat style): " + LogSanitizer.redact(json) + " (keys=" + verifiedClaims.keySet() + ")");
        } catch (Exception e) {
            LOGGER.severe("[AttributeUtil] Failed to save flat-style verified_claims: " + e.getMessage());
        }
    }

    /**
     * Saves extracted attributes and evidence directly to authentication session.
     *
     * <p>This method is used by REST API endpoints that don't have access to
     * the full AuthenticationFlowContext. Merges with existing claims and
     * persists to both session note locations.
     *
     * @param session the authentication session
     * @param revealedAttrs the extracted credential attributes
     * @param evidenceAttrs the verification evidence items
     */
    public static void saveToUserSessionNote(AuthenticationSessionModel session, Map<String, String> revealedAttrs, List<Map<String, Object>> evidenceAttrs) {
        try {
            Map<String, Object> verifiedClaims = loadOrInitVerifiedClaims(session);

            Map<String, Object> existingClaims = (Map<String, Object>)verifiedClaims.get("claims");
            List<Map<String, Object>> existingEvidence = (List<Map<String, Object>>)((Map)verifiedClaims.get("verification")).get("evidence");
            int claimsBefore = existingClaims.size();
            int evidenceBefore = existingEvidence.size();

            LOGGER.info("[AttributeUtil] merge-start mode=rest incomingClaims=" + revealedAttrs.size() +
                    ", incomingEvidence=" + evidenceAttrs.size() +
                    ", existingClaims=" + claimsBefore +
                    ", existingEvidence=" + evidenceBefore);

            for (Map.Entry<String, String> entry : revealedAttrs.entrySet())
                existingClaims.put(entry.getKey(), entry.getValue());
            existingEvidence.addAll(evidenceAttrs);
            String json = mapper.writeValueAsString(verifiedClaims);

            LOGGER.info("[AttributeUtil] merge-end mode=rest totalClaims=" + existingClaims.size() +
                    ", totalEvidence=" + existingEvidence.size() +
                    ", claimKeys=" + existingClaims.keySet());

            session.setUserSessionNote(SSISessionConstants.VERIFIED_CLAIMS, json);
            session.setAuthNote(SSISessionConstants.VERIFIED_CLAIMS, json);

            LOGGER.info("[AttributeUtil] verified_claims saved via REST API: " + LogSanitizer.redact(json) + " (keys=" + verifiedClaims.keySet() + ")");
        } catch (Exception e) {
            LOGGER.severe("[AttributeUtil] Failed to save verified_claims via REST API: " + e.getMessage());
        }
    }

    /**
     * Retrieves grouped attributes from the session.
     *
     * <p>Reads the "ssi_attrs_grouped_array" session note which contains
     * attributes organized by credential alias.
     *
     * @param session the authentication session
     * @return a list of grouped attribute maps; empty list if not found
     */
    public static List<Map<String, Map<String, String>>> getGroupedAttributes(AuthenticationSessionModel session) {
        try {
            String json = session.getAuthNote("ssi_attrs_grouped_array");
            if (json == null || json.isBlank())
                return Collections.emptyList();
            return (List<Map<String, Map<String, String>>>)mapper.readValue(json, new TypeReference<List<Map<String, Map<String, String>>>>() {

            });
        } catch (Exception e) {
            LOGGER.warning("[AttributeUtil] Failed to get nested attributes: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Retrieves all attributes as a flat map.
     *
     * <p>Flattens grouped attributes into a single map, merging all
     * attribute values from all credential aliases.
     *
     * @param session the authentication session
     * @return a flat map of all attribute names to values
     */
    public static Map<String, String> getFlattenedAttributes(AuthenticationSessionModel session) {
        Map<String, String> flat = new HashMap<>();
        try {
            List<Map<String, Map<String, String>>> grouped = getGroupedAttributes(session);
            for (Map<String, Map<String, String>> aliasEntry : grouped) {
                for (Map<String, String> attrs : aliasEntry.values())
                    flat.putAll(attrs);
            }
        } catch (Exception e) {
            LOGGER.warning("[AttributeUtil] Failed to flatten attributes: " + e.getMessage());
        }
        return flat;
    }

    /**
     * Inserts a value into a nested map structure using dot notation path.
     *
     * <p>Supports array notation for list indices (e.g., "items[0].name").
     *
     * @param root the root map to modify
     * @param path the dot-separated path with optional array indices
     * @param value the value to insert
     */
    private static void insertNestedValue(Map<String, Object> root, String path, String value) {
        String[] parts = path.split("\\.");
        Map<String, Object> current = root;
        for (int i = 0; i < parts.length; i++) {
            String key = parts[i];
            if (key.contains("[")) {
                String arrayKey = key.substring(0, key.indexOf("["));
                int index = Integer.parseInt(key.substring(key.indexOf("[") + 1, key.indexOf("]")));
                List<Object> list = (List<Object>)current.computeIfAbsent(arrayKey, k -> new ArrayList());
                for (; list.size() <= index; list.add(new HashMap<>()));
                if (i == parts.length - 1) {
                    list.set(index, value);
                } else {
                    current = (Map<String, Object>)list.get(index);
                }
            } else if (i == parts.length - 1) {
                current.put(key, value);
            } else {
                current = (Map<String, Object>)current.computeIfAbsent(key, k -> new HashMap<>());
            }
        }
    }
}
