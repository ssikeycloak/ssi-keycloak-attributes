package kodrat.keycloak.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONObject;
import kodrat.keycloak.constant.SSISessionConstants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;

/**
 * Utility class for accessing SSI authenticator configuration from multiple sources.
 *
 * <p>This class provides a unified interface for reading configuration values from
 * both the Keycloak authenticator context (admin console configuration) and
 * authentication session notes (REST API path). It handles legacy configuration
 * key names for backward compatibility.
 *
 * <h2>Configuration Sources</h2>
 * <p>Configuration can come from two sources:
 * <ol>
 *   <li><strong>Authenticator Config:</strong> Set via Keycloak Admin Console
 *       in Authentication → SSI Auth → Config</li>
 *   <li><strong>Session Notes:</strong> Stored during authenticator flow for
 *       access by REST API endpoints</li>
 * </ol>
 *
 * <h2>Configuration Keys</h2>
 * <table border="1">
 *   <caption>Available Configuration Parameters</caption>
 *   <tr><th>Key</th><th>Description</th><th>Example</th></tr>
 *   <tr><td>{@code did_method}</td><td>DID method to use</td><td>"sov" or "web"</td></tr>
 *   <tr><td>{@code ssi_endpoint}</td><td>SSI agent URL</td><td>"https://aca-py.example.com"</td></tr>
 *   <tr><td>{@code ssi_bearer_token}</td><td>Auth token for agent</td><td>"eyJ..."</td></tr>
 *   <tr><td>{@code proof_request_json}</td><td>Indy proof request</td><td>'{"attributes": ["name"]}'</td></tr>
 *   <tr><td>{@code requested_credential}</td><td>OpenID4VC config</td><td>'{"credential_type": "..."}'</td></tr>
 *   <tr><td>{@code subject_did}</td><td>Subject DID constraint</td><td>"did:sov:..."</td></tr>
 *   <tr><td>{@code issuer_did}</td><td>Issuer DID constraint</td><td>"did:sov:..."</td></tr>
 * </table>
 *
 * <h2>Legacy Configuration Keys</h2>
 * <p>For backward compatibility, the following legacy keys are supported:
 * <ul>
 *   <li>{@code ssi_token} → {@code ssi_bearer_token}</li>
 *   <li>{@code bearer_token} → {@code ssi_bearer_token}</li>
 * </ul>
 *
 * <h2>UI Configuration</h2>
 * <p>Custom UI text can be configured:
 * <ul>
 *   <li>{@code ui_consent_title} - Consent page title</li>
 *   <li>{@code ui_consent_description} - Consent page description</li>
 *   <li>{@code ui_required_data_title} - Required data section title</li>
 *   <li>{@code ui_privacy_title} - Privacy section title</li>
 *   <li>{@code ui_privacy_description} - Privacy section description</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is stateless and all methods are static. It is safe to call from
 * multiple threads concurrently.
 *
 * @see AttributeUtil
 * @see SSISessionConstants
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class ConfigUtils {

    private static final ObjectMapper mapper = new ObjectMapper();

    private ConfigUtils() {}

    /**
     * Extracts schema ID from a JSON string.
     *
     * <p>Supports both snake_case ({@code schema_id}) and camelCase ({@code schemaId})
     * for backward compatibility. Priority: {@code schema_id} > {@code schemaId}.
     *
     * @param jsonString the JSON string to parse
     * @return the schema ID if found, {@code null} otherwise
     */
    public static String extractSchemaId(String jsonString) {
        if (jsonString == null || jsonString.isEmpty()) {
            return null;
        }
        try {
            JsonNode root = mapper.readTree(jsonString);
            if (root.has("schema_id") && !root.get("schema_id").isNull()) {
                return root.get("schema_id").asText();
            }
            if (root.has("schemaId") && !root.get("schemaId").isNull()) {
                return root.get("schemaId").asText();
            }
        } catch (Exception e) {
        }
        return null;
    }
    
    /**
     * Extracts schema ID from a JsonNode.
     *
     * <p>Supports both snake_case ({@code schema_id}) and camelCase ({@code schemaId})
     * for backward compatibility. Priority: {@code schema_id} > {@code schemaId}.
     *
     * @param jsonNode the JsonNode to parse
     * @return the schema ID if found, {@code null} otherwise
     */
    public static String extractSchemaId(JsonNode jsonNode) {
        if (jsonNode == null || jsonNode.isNull()) {
            return null;
        }
        if (jsonNode.has("schema_id") && !jsonNode.get("schema_id").isNull()) {
            return jsonNode.get("schema_id").asText();
        }
        if (jsonNode.has("schemaId") && !jsonNode.get("schemaId").isNull()) {
            return jsonNode.get("schemaId").asText();
        }
        return null;
    }

    /**
     * Gets the DID method from authenticator context.
     *
     * <p>First checks the authenticator config, then falls back to session note.
     *
     * @param context the authentication flow context
     * @return the DID method ("sov" or "web"), may be {@code null}
     */
    public static String getDIDMethod(AuthenticationFlowContext context) {
        String fromConfig = getConfigValue(context, "did_method");
        if (fromConfig != null && !fromConfig.isBlank()) {
            return fromConfig;
        }
        return context.getAuthenticationSession().getAuthNote(SSISessionConstants.DID_METHOD);
    }

    /**
     * Gets the DID method from authentication session.
     *
     * <p>Reads from the session note set during authenticator flow.
     *
     * @param session the authentication session
     * @return the DID method, may be {@code null}
     */
    public static String getDIDMethod(AuthenticationSessionModel session) {
        return session.getAuthNote(SSISessionConstants.DID_METHOD);
    }

    /**
     * Gets the SSI endpoint from authentication session.
     *
     * @param session the authentication session
     * @return the SSI endpoint URL, may be {@code null}
     */
    public static String getSSIEndpoint(AuthenticationSessionModel session) {
        return session.getAuthNote(SSISessionConstants.SSI_ENDPOINT);
    }

    /**
     * Gets the bearer token from authentication session.
     *
     * <p>Checks multiple session note keys for backward compatibility:
     * <ol>
     *   <li>{@code ssi_bearer_token} (preferred)</li>
     *   <li>{@code ssi_token} (legacy)</li>
     *   <li>{@code bearer_token} (legacy, deprecated)</li>
     * </ol>
     *
     * @param session the authentication session
     * @return the bearer token, may be {@code null}
     */
    public static String getBearerToken(AuthenticationSessionModel session) {
        String token = session.getAuthNote(SSISessionConstants.SSI_BEARER_TOKEN);
        if (token != null && !token.isBlank()) {
            return token;
        }

        token = session.getAuthNote(SSISessionConstants.SSI_TOKEN);
        if (token != null && !token.isBlank()) {
            return token;
        }

        token = session.getAuthNote("bearer_token");
        if (token != null && !token.isBlank()) {
            return token;
        }

        return null;
    }

    /**
     * Gets the schema ID from proof request configuration.
     *
     * @param context the authentication flow context
     * @return the schema ID, may be {@code null}
     */
    public static String getSchemaId(AuthenticationFlowContext context) {
        String json = getConfigValue(context, "proof_request_json");
        return extractSchemaId(json);
    }

    /**
     * Gets the SSI endpoint from authenticator context.
     *
     * <p>First checks the authenticator config, then falls back to session note.
     *
     * @param context the authentication flow context
     * @return the SSI endpoint URL, may be {@code null}
     */
    public static String getSSIEndpoint(AuthenticationFlowContext context) {
        String fromConfig = getConfigValue(context, "ssi_endpoint");
        if (fromConfig != null && !fromConfig.isBlank()) {
            return fromConfig;
        }
        return context.getAuthenticationSession().getAuthNote(SSISessionConstants.SSI_ENDPOINT);
    }

    /**
     * Gets the bearer token from authenticator context.
     *
     * <p>Checks multiple configuration keys for backward compatibility:
     * <ol>
     *   <li>{@code ssi_bearer_token} (preferred)</li>
     *   <li>{@code ssi_token} (legacy)</li>
     *   <li>{@code bearer_token} (legacy, deprecated)</li>
     * </ol>
     *
     * <p>Also checks session notes as final fallback.
     *
     * @param context the authentication flow context
     * @return the bearer token, may be {@code null}
     */
    public static String getBearerToken(AuthenticationFlowContext context) {
        String fromConfig = getConfigValue(context, "ssi_bearer_token");
        if (fromConfig != null && !fromConfig.isBlank()) {
            return fromConfig;
        }

        fromConfig = getConfigValue(context, "ssi_token");
        if (fromConfig != null && !fromConfig.isBlank()) {
            return fromConfig;
        }

        fromConfig = getConfigValue(context, "bearer_token");
        if (fromConfig != null && !fromConfig.isBlank()) {
            return fromConfig;
        }

        String tokenFromSession = context.getAuthenticationSession().getAuthNote(SSISessionConstants.SSI_BEARER_TOKEN);
        if (tokenFromSession != null && !tokenFromSession.isBlank()) {
            return tokenFromSession;
        }
        tokenFromSession = context.getAuthenticationSession().getAuthNote(SSISessionConstants.SSI_TOKEN);
        if (tokenFromSession != null && !tokenFromSession.isBlank()) {
            return tokenFromSession;
        }
        return context.getAuthenticationSession().getAuthNote("bearer_token");
    }

    /**
     * Gets the proof request JSON as a JsonNode.
     *
     * @param context the authentication flow context
     * @return the proof request JSON node, may be {@code null}
     * @throws RuntimeException if the JSON is invalid
     */
    public static JsonNode getProofRequestJson(AuthenticationFlowContext context) {
        String json = getConfigValue(context, "proof_request_json");
        if (json == null || json.isEmpty()) return null;

        try {
            return mapper.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Invalid JSON in 'proof_request_json'", e);
        }
    }

    /**
     * Gets the list of requested attributes from configuration.
     *
     * <p>Extracts attributes from:
     * <ol>
     *   <li>{@code proof_request_json.attributes} (Indy format)</li>
     *   <li>{@code requested_credential.attributes} (OpenID4VC format)</li>
     *   <li>Default attributes if neither is configured</li>
     * </ol>
     *
     * @param context the authentication flow context
     * @return list of attribute names; never empty
     */
    public static java.util.List<String> getRequestedAttributes(AuthenticationFlowContext context) {
        String proofRequestJson = getConfigValue(context, "proof_request_json");
        java.util.List<String> attributes = extractAttributesFromJson(proofRequestJson);
        if (!attributes.isEmpty()) {
            return attributes;
        }

        String requestedCredentialJson = getConfigValue(context, "requested_credential");
        attributes = extractAttributesFromJson(requestedCredentialJson);
        if (!attributes.isEmpty()) {
            return attributes;
        }

        return java.util.List.of("name", "NIK", "email", "phone");
    }

    /**
     * Extracts attributes array from a JSON string.
     *
     * @param json the JSON string containing an "attributes" array
     * @return list of attribute names; empty list if not found or invalid
     */
    private static java.util.List<String> extractAttributesFromJson(String json) {
        if (json == null || json.isEmpty()) {
            return java.util.List.of();
        }

        try {
            JsonNode root = mapper.readTree(json);
            JsonNode attrs = root.get("attributes");
            if (attrs != null && attrs.isArray()) {
                java.util.List<String> attributes = new java.util.ArrayList<>();
                for (JsonNode attr : attrs) {
                    String value = attr.asText();
                    if (value != null && !value.isBlank()) {
                        attributes.add(value);
                    }
                }
                return attributes;
            }
        } catch (Exception ignored) {
        }
        return java.util.List.of();
    }

    /**
     * Gets a configuration value from authenticator config.
     *
     * @param context the authentication flow context
     * @param key the configuration key
     * @return the configuration value, may be {@code null}
     */
    private static String getConfigValue(AuthenticationFlowContext context, String key) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config != null && config.getConfig() != null) {
            return config.getConfig().get(key);
        }
        return null;
    }

    /**
     * Gets the credential type from configuration map.
     *
     * <p>Extracts from {@code requested_credential.credential_type}.
     *
     * @param config the configuration map
     * @return the credential type, defaults to "VerifiableDiploma"
     */
    public static String getCredentialType(Map<String, String> config) {
        String defaultJson = "{ \"credential_type\": \"VerifiableDiploma\" }";
        String requestedCredentialJson = config.getOrDefault("requested_credential", defaultJson);

        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode root = mapper.readTree(requestedCredentialJson);
            return root.path("credential_type").asText("VerifiableDiploma");
        } catch (Exception e) {
            return "VerifiableDiploma";
        }
    }

    /**
     * Gets the issuer DID from configuration.
     *
     * @param context the authentication flow context
     * @return the issuer DID, may be {@code null}
     */
    public static String getIssuerDid(AuthenticationFlowContext context) {
        String fromConfig = getConfigValue(context, "issuer_did");
        if (fromConfig != null && !fromConfig.isBlank()) {
            return fromConfig;
        }
        return context.getAuthenticationSession().getAuthNote("issuer_did");
    }

    /**
     * Gets a human-readable issuer name from the issuer DID.
     *
     * <p>Extracts readable parts from different DID formats:
     * <ul>
     *   <li>did:sov:{issuer}:{name}:{version} → returns issuer</li>
     *   <li>did:web:example.com → returns example.com</li>
     *   <li>did:key:... → returns "Key DID"</li>
     * </ul>
     *
     * @param context the authentication flow context
     * @return the issuer name, may be {@code null}
     */
    public static String getIssuerName(AuthenticationFlowContext context) {
        String issuerDid = getIssuerDid(context);
        if (issuerDid == null || issuerDid.isEmpty()) {
            return null;
        }

        if (issuerDid.startsWith("did:")) {
            String[] parts = issuerDid.split(":");
            if (parts.length >= 3) {
                if ("web".equals(parts[1]) && parts.length >= 3) {
                    return parts[2];
                } else if ("sov".equals(parts[1]) && parts.length >= 4) {
                    return parts[2];
                } else if ("key".equals(parts[1])) {
                    return "Key DID";
                }
            }
        }

        return issuerDid;
    }

    /**
     * Gets the schema name from the schema ID or credential type.
     *
     * <p>For Indy schemas, extracts the name from the schema ID format.
     * For OpenID4VC, uses the credential_type as a display name.
     *
     * @param context the authentication flow context
     * @return the schema name, may be {@code null}
     */
    public static String getSchemaName(AuthenticationFlowContext context) {
        String schemaId = getSchemaId(context);
        if (schemaId == null || schemaId.isEmpty()) {
            String requestedCredentialJson = getConfigValue(context, "requested_credential");
            if (requestedCredentialJson != null && !requestedCredentialJson.isEmpty()) {
                try {
                    JsonNode root = mapper.readTree(requestedCredentialJson);
                    String credentialType = root.path("credential_type").asText(null);
                    if (credentialType != null && !credentialType.isBlank()) {
                        return credentialType;
                    }
                } catch (Exception ignored) {
                }
            }
            return null;
        }

        if (schemaId.contains(":")) {
            String[] parts = schemaId.split(":");
            if (parts.length >= 4) {
                return parts[parts.length - 2];
            }
        }

        return schemaId;
    }

    /**
     * Gets the UI consent title from configuration.
     *
     * @param context the authentication flow context
     * @return the consent title, may be {@code null}
     */
    public static String getUiConsentTitle(AuthenticationFlowContext context) {
        return getConfigValue(context, "ui_consent_title");
    }

    /**
     * Gets the UI consent description from configuration.
     *
     * @param context the authentication flow context
     * @return the consent description, may be {@code null}
     */
    public static String getUiConsentDescription(AuthenticationFlowContext context) {
        return getConfigValue(context, "ui_consent_description");
    }

    /**
     * Gets the UI required data title from configuration.
     *
     * @param context the authentication flow context
     * @return the required data title, may be {@code null}
     */
    public static String getUiRequiredDataTitle(AuthenticationFlowContext context) {
        return getConfigValue(context, "ui_required_data_title");
    }

    /**
     * Gets the UI privacy title from configuration.
     *
     * @param context the authentication flow context
     * @return the privacy title, may be {@code null}
     */
    public static String getUiPrivacyTitle(AuthenticationFlowContext context) {
        return getConfigValue(context, "ui_privacy_title");
    }

    /**
     * Gets the UI privacy description from configuration.
     *
     * @param context the authentication flow context
     * @return the privacy description, may be {@code null}
     */
    public static String getUiPrivacyDescription(AuthenticationFlowContext context) {
        return getConfigValue(context, "ui_privacy_description");
    }
}
