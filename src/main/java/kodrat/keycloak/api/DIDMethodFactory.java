package kodrat.keycloak.api;

import java.util.Locale;
import kodrat.keycloak.config.ConfigUtils;
import kodrat.keycloak.constant.SSISessionConstants;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Factory for creating and configuring {@link DIDMethod} instances based on
 * authentication configuration.
 *
 * <p>This factory provides a centralized mechanism for instantiating the appropriate
 * DID method implementation (did:web, did:sov, etc.) based on configuration from
 * either the Keycloak authenticator context or REST API session notes.
 *
 * <h2>Design Pattern</h2>
 * <p>This factory implements the <strong>Factory Method</strong> pattern, encapsulating
 * the complexity of DID method selection and configuration. It supports two primary
 * instantiation paths:
 * <ul>
 *   <li><strong>Authenticator Context:</strong> Configuration read from authenticator
 *       config and saved to session for later use</li>
 *   <li><strong>REST API Session:</strong> Configuration read from previously saved
 *       session notes</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <h3>From Authenticator Context</h3>
 * <pre>{@code
 * @Override
 * public void authenticate(AuthenticationFlowContext context) {
 *     DIDMethod method = DIDMethodFactory.getMethod(context);
 *     method.handleAuthentication(context);
 * }
 * }</pre>
 *
 * <h3>From REST API Session</h3>
 * <pre>{@code
 * @GET
 * @Path("/status")
 * public Response checkStatus(@Context HttpHeaders headers) {
 *     AuthenticationSessionModel session = getSessionFromCookie(headers);
 *     DIDMethod method = DIDMethodFactory.getMethod(session);
 *     boolean received = method.hasReceivedPresentation(session);
 *     return Response.ok(received ? "received" : "waiting").build();
 * }
 * }</pre>
 *
 * <h2>Adding a New DID Method</h2>
 * <p>To add support for a new DID method:
 * <ol>
 *   <li>Create a new class extending {@link AbstractDIDMethod} (e.g., {@code DIDIon})</li>
 *   <li>Implement all required abstract methods</li>
 *   <li>Add a new case in {@link #getMethodFromRaw(String, String, String)} switch statement</li>
 *   <li>Update documentation to reflect the new method</li>
 * </ol>
 *
 * <p>Example addition:
 * <pre>{@code
 * case "ion" -> new DIDIon(endpoint, token);
 * }</pre>
 *
 * <h2>Configuration Persistence</h2>
 * <p>When creating a method from authenticator context, configuration is automatically
 * persisted to session notes for later retrieval by REST API endpoints. This includes:
 * <ul>
 *   <li>{@code did_method} - The selected DID method</li>
 *   <li>{@code ssi_endpoint} - The SSI agent endpoint URL</li>
 *   <li>{@code ssi_bearer_token} - Authentication token (also saved as legacy keys)</li>
 *   <li>{@code proof_request_json} - Proof request configuration</li>
 *   <li>{@code requested_credential} - Credential requirements</li>
 *   <li>{@code subject_did} / {@code issuer_did} - Validation constraints</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>This factory is stateless and all methods are static. It is safe to call from
 * multiple threads concurrently.
 *
 * @see DIDMethod
 * @see AbstractDIDMethod
 * @see DIDWeb
 * @see DIDSov
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class DIDMethodFactory {

    /**
     * Private constructor to prevent instantiation.
     * This is a utility class with only static methods.
     */
    private DIDMethodFactory() {
    }

    /**
     * Creates a DID method instance from the Keycloak authenticator context.
     *
     * <p>This method extracts configuration from the authenticator config and saves
     * it to the authentication session for later use by REST API endpoints. This
     * ensures configuration persistence across the authentication flow.
     *
     * <p>The following configuration values are extracted and saved:
     * <table border="1">
     *   <caption>Configuration Mapping</caption>
     *   <tr><th>Config Key</th><th>Session Note Key</th><th>Description</th></tr>
     *   <tr><td>{@code did_method}</td><td>{@code did_method}</td><td>DID method identifier</td></tr>
     *   <tr><td>{@code ssi_endpoint}</td><td>{@code ssi_endpoint}</td><td>SSI agent URL</td></tr>
     *   <tr><td>{@code bearer_token}</td><td>{@code ssi_bearer_token}</td><td>Auth token</td></tr>
     *   <tr><td>{@code proof_request_json}</td><td>{@code proof_request_json}</td><td>Proof config</td></tr>
     *   <tr><td>{@code requested_credential}</td><td>{@code requested_credential}</td><td>Credential spec</td></tr>
     *   <tr><td>{@code subject_did}</td><td>{@code subject_did}</td><td>Subject validation</td></tr>
     *   <tr><td>{@code issuer_did}</td><td>{@code issuer_did}</td><td>Issuer validation</td></tr>
     * </table>
     *
     * <p><strong>Note:</strong> The bearer token is also saved under legacy keys
     * ({@code ssi_token}, {@code bearer_token}) for backward compatibility with
     * existing deployments. These legacy keys are deprecated and will be removed
     * in a future version.
     *
     * @param context the Keycloak authentication flow context containing the
     *                authenticator configuration and authentication session
     * @return the appropriate {@link DIDMethod} instance configured with endpoint
     *         and authentication credentials
     * @throws IllegalArgumentException if the configured DID method is not supported
     * @throws NullPointerException if context is null
     * @see #getMethod(AuthenticationSessionModel)
     * @see #getMethodFromRaw(String, String, String)
     */
    public static DIDMethod getMethod(AuthenticationFlowContext context) {
        String method = ConfigUtils.getDIDMethod(context);
        String endpoint = ConfigUtils.getSSIEndpoint(context);
        String token = ConfigUtils.getBearerToken(context);
        String proofRequestJson = null;
        String requestedCredential = null;
        String subjectDid = null;
        String issuerDid = null;
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        if (configModel != null && configModel.getConfig() != null) {
            proofRequestJson = configModel.getConfig().get(SSISessionConstants.PROOF_REQUEST_JSON);
            requestedCredential = configModel.getConfig().get("requested_credential");
            subjectDid = configModel.getConfig().get("subject_did");
            issuerDid = configModel.getConfig().get("issuer_did");
        }

        context.getAuthenticationSession().setAuthNote(SSISessionConstants.DID_METHOD, method);
        context.getAuthenticationSession().setAuthNote(SSISessionConstants.SSI_ENDPOINT, endpoint);
        context.getAuthenticationSession().setAuthNote(SSISessionConstants.SSI_BEARER_TOKEN, token);
        if (token != null && !token.isBlank()) {
            context.getAuthenticationSession().setAuthNote(SSISessionConstants.SSI_TOKEN, token);
            context.getAuthenticationSession().setAuthNote("bearer_token", token);
        }
        if (proofRequestJson != null && !proofRequestJson.isBlank()) {
            context.getAuthenticationSession().setAuthNote(SSISessionConstants.PROOF_REQUEST_JSON, proofRequestJson);
        }
        if (requestedCredential != null && !requestedCredential.isBlank()) {
            context.getAuthenticationSession().setAuthNote("requested_credential", requestedCredential);
        }
        if (subjectDid != null && !subjectDid.isBlank()) {
            context.getAuthenticationSession().setAuthNote("subject_did", subjectDid);
        }
        if (issuerDid != null && !issuerDid.isBlank()) {
            context.getAuthenticationSession().setAuthNote("issuer_did", issuerDid);
        }

        return getMethodFromRaw(method, endpoint, token);
    }

    /**
     * Creates a DID method instance from an authentication session.
     *
     * <p>This method is used by REST API endpoints that need to access DID method
     * functionality without access to the full authenticator context. Configuration
     * is read from session notes that were previously saved by
     * {@link #getMethod(AuthenticationFlowContext)}.
     *
     * <p><strong>Prerequisites:</strong> The session must have been initialized
     * by the authenticator flow, which saves the necessary configuration to
     * session notes.
     *
     * @param session the authentication session containing saved configuration notes
     * @return the appropriate {@link DIDMethod} instance configured with endpoint
     *         and authentication credentials
     * @throws IllegalArgumentException if the DID method in session is not supported
     * @throws NullPointerException if session is null
     * @see #getMethod(AuthenticationFlowContext)
     * @see #getMethodFromRaw(String, String, String)
     */
    public static DIDMethod getMethod(AuthenticationSessionModel session) {
        String method = ConfigUtils.getDIDMethod(session);
        String endpoint = ConfigUtils.getSSIEndpoint(session);
        String token = ConfigUtils.getBearerToken(session);

        return getMethodFromRaw(method, endpoint, token);
    }

    /**
     * Creates a DID method instance from raw configuration parameters.
     *
     * <p>This is the central dispatch point for all DID method creation. It maps
     * method identifiers to their corresponding implementation classes.
     *
     * <h3>Supported Methods</h3>
     * <table border="1">
     *   <caption>Supported DID Methods</caption>
     *   <tr><th>Identifier</th><th>Implementation</th><th>Protocol</th></tr>
     *   <tr><td>{@code sov}</td><td>{@link DIDSov}</td><td>DIDComm / Indy</td></tr>
     *   <tr><td>{@code web}</td><td>{@link DIDWeb}</td><td>OpenID4VC</td></tr>
     * </table>
     *
     * <h3>Extending with New Methods</h3>
     * <p>To add a new DID method:
     * <pre>{@code
     * return switch (method.trim().toLowerCase(Locale.ROOT)) {
     *     case "sov" -> new DIDSov(endpoint, token);
     *     case "web" -> new DIDWeb(endpoint, token);
     *     case "ion" -> new DIDIon(endpoint, token);  // New method
     *     default -> throw new IllegalArgumentException("Unsupported DID method: " + method);
     * };
     * }</pre>
     *
     * @param method the DID method identifier (case-insensitive, e.g., "sov", "web")
     * @param endpoint the base URL of the SSI agent (must be a valid HTTP/HTTPS URL)
     * @param token the bearer token for SSI agent authentication; may be {@code null}
     *              or blank if authentication is not required
     * @return the appropriate {@link DIDMethod} instance
     * @throws IllegalArgumentException if method is null, blank, or not supported
     */
    public static DIDMethod getMethodFromRaw(String method, String endpoint, String token) {
        if (method == null || method.isBlank()) {
            throw new IllegalArgumentException("Unsupported DID method: null or empty");
        }

        return switch (method.trim().toLowerCase(Locale.ROOT)) {
            case "sov" -> new DIDSov(endpoint, token);
            case "web" -> new DIDWeb(endpoint, token);
            default -> throw new IllegalArgumentException("Unsupported DID method: " + method);
        };
    }
}
