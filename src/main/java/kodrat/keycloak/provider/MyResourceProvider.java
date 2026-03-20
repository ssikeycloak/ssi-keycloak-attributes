package kodrat.keycloak.provider;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import kodrat.keycloak.api.DIDMethod;
import kodrat.keycloak.api.DIDMethodFactory;
import kodrat.keycloak.api.SSIResult;
import kodrat.keycloak.constant.SSIReasonCode;
import kodrat.keycloak.constant.SSISessionConstants;
import kodrat.keycloak.constant.SSIStatus;
import kodrat.keycloak.service.QRCodeService;
import kodrat.keycloak.service.SSIStateResetService;
import kodrat.keycloak.util.LogSanitizer;
import kodrat.keycloak.util.SSIFlowLogger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;
import java.util.Map;
import jakarta.ws.rs.core.MediaType;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.jboss.logging.Logger;
import java.nio.charset.StandardCharsets;
import java.net.URLEncoder;

/**
 * REST API provider for SSI authentication status polling and flow control.
 *
 * <p>This provider exposes HTTP endpoints that allow the frontend to poll for
 * verification status, generate QR codes, and retry failed authentication attempts.
 * It serves as the bridge between the browser-based UI and the server-side
 * authentication flow.
 *
 * <h2>Endpoints</h2>
 * <table border="1">
 *   <caption>Available REST Endpoints</caption>
 *   <tr><th>Method</th><th>Path</th><th>Description</th></tr>
 *   <tr><td>GET</td><td>/status</td><td>Poll for current SSI verification status</td></tr>
 *   <tr><td>GET</td><td>/qr</td><td>Generate QR code PNG image</td></tr>
 *   <tr><td>POST</td><td>/retry</td><td>Reset flow and allow retry</td></tr>
 * </table>
 *
 * <h2>Response Format</h2>
 * <p>All endpoints return JSON with the following common fields:
 * <table border="1">
 *   <caption>Response Fields</caption>
 *   <tr><th>Field</th><th>Type</th><th>Description</th></tr>
 *   <tr><td>{@code status}</td><td>String</td><td>Current SSI status (waiting-connection, verifying, done, etc.)</td></tr>
 *   <tr><td>{@code reasonCode}</td><td>String</td><td>Machine-readable code for frontend handling</td></tr>
 *   <tr><td>{@code message}</td><td>String</td><td>Human-readable status message (Indonesian)</td></tr>
 *   <tr><td>{@code recoverable}</td><td>Boolean</td><td>Whether retry is possible</td></tr>
 * </table>
 *
 * <h2>Authentication</h2>
 * <p>Endpoints support a transitional "soft mode" that allows unauthenticated requests
 * while logging them. This mode is controlled by the system property
 * {@code ssi.status.auth.soft.mode} (default: true).
 *
 * <h2>Cache Control</h2>
 * <p>All responses include cache-control headers to prevent caching:
 * <pre>
 * Cache-Control: no-store, no-cache, must-revalidate, max-age=0
 * Pragma: no-cache
 * Expires: 0
 * </pre>
 *
 * <h2>Flow Progression</h2>
 * <p>The /status endpoint implements the same 4-step flow as the authenticator:
 * <ol>
 *   <li>Wait for connection establishment</li>
 *   <li>Send proof request</li>
 *   <li>Wait for presentation</li>
 *   <li>Verify presentation</li>
 * </ol>
 *
 * <h2>Thread Safety</h2>
 * <p>This provider is thread-safe. Each request is handled independently with
 * its own authentication session lookup.
 *
 * @see SSIAuth
 * @see DIDMethod
 * @see SSIStateResetService
 * @see SSIFlowLogger
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public class MyResourceProvider implements RealmResourceProvider {
    
    private static final Logger LOGGER = Logger.getLogger(MyResourceProvider.class);
    
    private final KeycloakSession session;

    /**
     * Transitional mode flag for authentication enforcement.
     * When true, allows unauthorized requests but logs them.
     * Controlled by system property {@code ssi.status.auth.soft.mode}.
     */
    private static final boolean AUTH_SOFT_MODE = Boolean.parseBoolean(
            System.getProperty("ssi.status.auth.soft.mode", "true"));

    /**
     * Constructs a new provider instance with the given Keycloak session.
     *
     * @param keycloakSession the Keycloak session for accessing services
     */
    public MyResourceProvider(KeycloakSession keycloakSession) {
        this.session = keycloakSession;
    }

    /**
     * Returns this provider instance as the resource.
     *
     * @return this provider instance
     */
    @Override
    public Object getResource() {
        return this;
    }

    /**
     * Closes any resources held by this provider.
     * This provider holds no resources, so this is a no-op.
     */
    @Override
    public void close() {
    }

    /**
     * Main status polling endpoint for SSI verification progress.
     *
     * <p>This endpoint returns the current verification status and advances the
     * flow if possible. It implements the same 4-step verification flow as the
     * authenticator, allowing frontend JavaScript to poll for progress.
     *
     * <h3>Request Parameters</h3>
     * <table border="1">
     *   <caption>Query Parameters</caption>
     *   <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
     *   <tr><td>{@code sessionId}</td><td>Yes</td><td>Root authentication session ID</td></tr>
     *   <tr><td>{@code tabId}</td><td>Yes</td><td>Tab/execution ID within the session</td></tr>
     * </table>
     *
     * <h3>Response Codes</h3>
     * <ul>
     *   <li>200 OK - Status retrieved successfully</li>
     *   <li>400 Bad Request - Missing or invalid parameters</li>
     *   <li>401 Unauthorized - Authentication required (non-soft mode only)</li>
     *   <li>500 Internal Server Error - Unexpected error</li>
     * </ul>
     *
     * <h3>Response Examples</h3>
     * <pre>{@code
     * // Waiting for connection
     * {
     *   "status": "waiting-connection",
     *   "reasonCode": "IN_PROGRESS",
     *   "qrCodeUrl": "/realms/myrealm/custom-resource/qr?data=...",
     *   "message": "Menunggu wallet terhubung",
     *   "recoverable": true
     * }
     *
     * // Verification complete
     * {
     *   "status": "done",
     *   "reasonCode": "SUCCESS",
     *   "message": "Verifikasi berhasil!",
     *   "recoverable": false
     * }
     * }</pre>
     *
     * @param headers HTTP headers for authentication
     * @param sessionId the root authentication session ID
     * @param tabId the tab/execution ID
     * @return JSON response with status, reasonCode, message, and optional qrCodeUrl
     */
    @GET
    @Path("/status")
    @Produces(MediaType.APPLICATION_JSON)
    public Response statusSSI(
            @Context HttpHeaders headers,
            @QueryParam("sessionId") String sessionId,
            @QueryParam("tabId") String tabId
    ) {
        try {
            String normalizedSessionId = sessionId != null ? sessionId.trim() : null;
            String normalizedTabId = tabId != null ? tabId.trim() : null;

            AuthenticationManager.AuthResult authResult = checkAuthWithLogging();
            if (authResult == null && !AUTH_SOFT_MODE) {
                LOGGER.warn("[MyResourceProvider] Unauthorized access attempt to /status endpoint");
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity(Map.of(
                                "status", "error",
                                "reasonCode", SSIReasonCode.UNAUTHORIZED,
                                "message", "Authentication required",
                                "recoverable", false
                        ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            } else if (authResult == null) {
                LOGGER.info("[MyResourceProvider] /status accessed without auth (soft mode) - sessionId: " + LogSanitizer.maskIdentifier(normalizedSessionId));
            }

            if (normalizedSessionId == null || normalizedSessionId.isBlank() || normalizedTabId == null || normalizedTabId.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of(
                                "status", "error",
                                "reasonCode", SSIReasonCode.MISSING_PARAMS,
                                "message", "Missing sessionId or tabId",
                                "recoverable", false
                        ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

            LOGGER.info("[MyResourceProvider] /status request - sessionId=" + LogSanitizer.maskIdentifier(normalizedSessionId)
                    + ", tabId=" + LogSanitizer.maskIdentifier(normalizedTabId));

            var realm = session.getContext().getRealm();
            var rootSession = session.authenticationSessions().getRootAuthenticationSession(realm, normalizedSessionId);

            if (rootSession == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of(
                                "status", "error",
                                "reasonCode", SSIReasonCode.SESSION_EXPIRED,
                                "message", "Session has expired. Please restart login.",
                                "recoverable", false
                        ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

            AuthenticationSessionModel authSession = rootSession.getAuthenticationSessions().get(normalizedTabId);
            if (authSession == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of(
                                "status", "error",
                                "reasonCode", SSIReasonCode.INVALID_TAB,
                                "message", "Invalid or expired authentication tab",
                                "recoverable", false
                        ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

            DIDMethod method = DIDMethodFactory.getMethod(authSession);

            String ssiStatus = authSession.getAuthNote(SSISessionConstants.SSI_STATUS);
            if (ssiStatus == null) ssiStatus = "";
            LOGGER.info("[MyResourceProvider] Current SSI status: " + ssiStatus);

            if (SSIStatus.DONE.getValue().equals(ssiStatus)) {
                SSIFlowLogger.logSuccess(authSession, 1);
                return Response.ok(Map.of(
                        "status", SSIStatus.DONE.getValue(),
                        "reasonCode", SSIReasonCode.SUCCESS,
                        "message", "Verifikasi berhasil!",
                        "recoverable", false
                ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

            if (SSIStatus.INVALID.getValue().equals(ssiStatus)) {
                SSIFlowLogger.logFailure(authSession, "Invalid verification state", SSIReasonCode.INVALID);
                return Response.ok(Map.of(
                        "status", SSIStatus.INVALID.getValue(),
                        "reasonCode", SSIReasonCode.INVALID,
                        "message", "Verifikasi gagal. Silakan coba lagi.",
                        "recoverable", true
                ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

            if (!method.isConnectionEstablished(authSession)) {
                LOGGER.info("[MyResourceProvider] Step 1: Waiting for SSI connection...");
                authSession.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.WAITING_CONNECTION.getValue());
                SSIFlowLogger.logWait(authSession, "connection");

                String latestInvitationUrl = authSession.getAuthNote(SSISessionConstants.INVITATION_URL);
                if (latestInvitationUrl == null || latestInvitationUrl.isBlank()) {
                    LOGGER.info("[MyResourceProvider] No invitation URL found, creating new invitation");
                    latestInvitationUrl = method.createInvitation(authSession);
                }
                if (latestInvitationUrl == null) {
                    latestInvitationUrl = "";
                }
                String latestQrCodeUrl = buildQrProxyUrl(latestInvitationUrl);

                return Response.ok(Map.of(
                        "status", SSIStatus.WAITING_CONNECTION.getValue(),
                        "reasonCode", SSIReasonCode.IN_PROGRESS,
                        "qrCodeUrl", latestQrCodeUrl,
                        "message", "Menunggu wallet terhubung",
                        "recoverable", true
                ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

            String connectionId = authSession.getAuthNote(SSISessionConstants.CONNECTION_ID);
            LOGGER.info("[MyResourceProvider] Connection established: " + LogSanitizer.maskIdentifier(connectionId));
            SSIFlowLogger.logConnect(authSession, connectionId);

            String presExId = authSession.getAuthNote(SSISessionConstants.PRES_EX_ID);
            if (presExId == null || presExId.isBlank()) {
                SSIResult proofResult = method.sendProofRequest(authSession);
                if (!proofResult.isDone()) {
                    LOGGER.info("[MyResourceProvider] Step 2: Proof request pending...");
                    authSession.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.WAITING_PROOF.getValue());
                    return Response.ok(Map.of(
                                    "status", SSIStatus.WAITING_PROOF.getValue(),
                                    "reasonCode", SSIReasonCode.IN_PROGRESS,
                                    "connectionId", connectionId != null ? connectionId : "",
                                    "message", "Terhubung! Menyiapkan permintaan verifikasi",
                                    "recoverable", true
                            ))
                            .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                            .header("Pragma", "no-cache")
                            .header("Expires", "0")
                            .build();
                }

                LOGGER.info("[MyResourceProvider] Step 2: Proof request sent");
                authSession.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.PROOF_REQUESTED.getValue());
                presExId = proofResult.getPresExId();
                if (presExId != null && !presExId.isBlank()) {
                    authSession.setAuthNote(SSISessionConstants.PRES_EX_ID, presExId);
                }
            }

            String latestInvitationUrl = authSession.getAuthNote(SSISessionConstants.INVITATION_URL);
            if (latestInvitationUrl == null) {
                latestInvitationUrl = "";
            }
            String latestQrCodeUrl = buildQrProxyUrl(latestInvitationUrl);

            if (!method.hasReceivedPresentation(authSession)) {
                LOGGER.info("[MyResourceProvider] Step 3: Waiting for credential presentation...");
                authSession.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.WAITING_PRESENTATION.getValue());
                return Response.ok(Map.of(
                        "status", SSIStatus.WAITING_PRESENTATION.getValue(),
                        "reasonCode", SSIReasonCode.IN_PROGRESS,
                        "connectionId", connectionId != null ? connectionId : "",
                        "qrCodeUrl", latestQrCodeUrl,
                        "message", "Terhubung! Menunggu verifikasi identitas",
                        "recoverable", true
                ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

            boolean verified = method.verifyPresentation(authSession);
            if (verified) {
                LOGGER.info("[MyResourceProvider] Step 4: Verification successful");
                authSession.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.DONE.getValue());
                SSIFlowLogger.logVerify(authSession, true, 1);
                SSIFlowLogger.logSuccess(authSession, 1);
                return Response.ok(Map.of(
                        "status", SSIStatus.DONE.getValue(),
                        "reasonCode", SSIReasonCode.SUCCESS,
                        "connectionId", connectionId != null ? connectionId : "",
                        "message", "Verifikasi berhasil!",
                        "recoverable", false
                ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            } else {
                LOGGER.warn("[MyResourceProvider] Step 4: Verification failed");
                authSession.setAuthNote(SSISessionConstants.SSI_STATUS, SSIStatus.INVALID.getValue());
                SSIFlowLogger.logVerify(authSession, false, 0);
                SSIFlowLogger.logFailure(authSession, "Presentation verification failed", SSIReasonCode.INVALID);
                return Response.ok(Map.of(
                        "status", SSIStatus.INVALID.getValue(),
                        "reasonCode", SSIReasonCode.INVALID,
                        "connectionId", connectionId != null ? connectionId : "",
                        "message", "Verifikasi gagal. Silakan coba lagi.",
                        "recoverable", true
                ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

        } catch (Exception e) {
            LOGGER.error("[MyResourceProvider] Error in /status endpoint: " + LogSanitizer.redact(e.getMessage()));
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of(
                            "status", "error",
                            "reasonCode", SSIReasonCode.INTERNAL_ERROR,
                            "message", "Internal error occurred",
                            "recoverable", false
                    ))
                    .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                    .header("Pragma", "no-cache")
                    .header("Expires", "0")
                    .build();
        }
    }

    /**
     * Generates a QR code PNG image from the provided data.
     *
     * <p>This endpoint allows the frontend to display QR codes without embedding
     * large data URLs in the HTML. The QR code is generated server-side and
     * returned as a PNG image.
     *
     * <h3>Request Parameters</h3>
     * <table border="1">
     *   <caption>Query Parameters</caption>
     *   <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
     *   <tr><td>{@code data}</td><td>Yes</td><td>The data to encode in the QR code</td></tr>
     * </table>
     *
     * <h3>Response Codes</h3>
     * <ul>
     *   <li>200 OK - PNG image returned</li>
     *   <li>400 Bad Request - Missing or blank data parameter</li>
     *   <li>500 Internal Server Error - QR code generation failed</li>
     * </ul>
     *
     * @param data the data to encode in the QR code (typically an invitation URL)
     * @return PNG image response with content-type image/png
     */
    @GET
    @Path("/qr")
    @Produces("image/png")
    public Response qrCode(@QueryParam("data") String data) {
        try {
            if (data == null || data.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST).build();
            }
            byte[] png = QRCodeService.generateQRCodePng(data);
            return Response.ok(png, "image/png")
                    .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                    .header("Pragma", "no-cache")
                    .header("Expires", "0")
                    .build();
        } catch (Exception e) {
            LOGGER.warn("[MyResourceProvider] Failed to generate QR image: " + LogSanitizer.redact(e.getMessage()));
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
        }
    }


    /**
     * Resets SSI flow state and allows retry without full login restart.
     *
     * <p>This endpoint clears all transient session notes and generates a new flow ID,
     * allowing users to retry verification after a failure without restarting the
     * entire login process.
     *
     * <h3>Request Parameters</h3>
     * <table border="1">
     *   <caption>Form Parameters</caption>
     *   <tr><th>Parameter</th><th>Required</th><th>Description</th></tr>
     *   <tr><td>{@code sessionId}</td><td>Yes</td><td>Root authentication session ID</td></tr>
     *   <tr><td>{@code tabId}</td><td>Yes</td><td>Tab/execution ID within the session</td></tr>
     * </table>
     *
     * <h3>Response Codes</h3>
     * <ul>
     *   <li>200 OK - Reset successful, returns new flow ID</li>
     *   <li>400 Bad Request - Missing or invalid parameters</li>
     *   <li>401 Unauthorized - Authentication required (non-soft mode only)</li>
     *   <li>500 Internal Server Error - Reset failed</li>
     * </ul>
     *
     * <h3>Response Example</h3>
     * <pre>{@code
     * {
     *   "status": "reset-ok",
     *   "reasonCode": "RESET_OK",
     *   "flowId": "uuid-of-new-flow",
     *   "previousStatus": "invalid",
     *   "message": "SSI flow reset successfully. Ready to retry.",
     *   "nextStep": "poll",
     *   "recoverable": true
     * }
     * }</pre>
     *
     * @param sessionId the root authentication session ID
     * @param tabId the tab/execution ID
     * @return JSON response with reset status and new flow ID
     */
    @POST
    @Path("/retry")
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrySSI(
            @FormParam("sessionId") String sessionId,
            @FormParam("tabId") String tabId
    ) {
        try {
            String normalizedSessionId = sessionId != null ? sessionId.trim() : null;
            String normalizedTabId = tabId != null ? tabId.trim() : null;

            AuthenticationManager.AuthResult authResult = checkAuthWithLogging();
            if (authResult == null && !AUTH_SOFT_MODE) {
                LOGGER.warn("[MyResourceProvider] Unauthorized access attempt to /retry endpoint");
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity(Map.of(
                                "status", "error",
                                "reasonCode", SSIReasonCode.UNAUTHORIZED,
                                "message", "Authentication required",
                                "recoverable", false
                        ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            } else if (authResult == null) {
                LOGGER.info("[MyResourceProvider] /retry accessed without auth (soft mode) - sessionId: " + LogSanitizer.maskIdentifier(normalizedSessionId));
            }

            if (normalizedSessionId == null || normalizedSessionId.isBlank() || normalizedTabId == null || normalizedTabId.isBlank()) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of(
                                "status", "error",
                                "reasonCode", SSIReasonCode.MISSING_PARAMS,
                                "message", "Missing sessionId or tabId",
                                "recoverable", false
                        ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

            LOGGER.info("[MyResourceProvider] /retry request - sessionId=" + LogSanitizer.maskIdentifier(normalizedSessionId)
                    + ", tabId=" + LogSanitizer.maskIdentifier(normalizedTabId));

            var realm = session.getContext().getRealm();
            var rootSession = session.authenticationSessions().getRootAuthenticationSession(realm, normalizedSessionId);

            if (rootSession == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of(
                                "status", "error",
                                "reasonCode", SSIReasonCode.SESSION_EXPIRED,
                                "message", "Session has expired. Please restart login.",
                                "recoverable", false
                        ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

            AuthenticationSessionModel authSession = rootSession.getAuthenticationSessions().get(normalizedTabId);
            if (authSession == null) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(Map.of(
                                "status", "error",
                                "reasonCode", SSIReasonCode.INVALID_TAB,
                                "message", "Invalid or expired authentication tab",
                                "recoverable", false
                        ))
                        .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                        .header("Pragma", "no-cache")
                        .header("Expires", "0")
                        .build();
            }

            String previousStatus = authSession.getAuthNote(SSISessionConstants.SSI_STATUS);
            LOGGER.info("[MyResourceProvider] Resetting SSI flow - previous status: " + previousStatus);
            
            SSIFlowLogger.logRetry(authSession, previousStatus);

            String newFlowId = SSIStateResetService.resetForRetry(authSession);

            LOGGER.info("[MyResourceProvider] SSI retry successful - new flowId: " + LogSanitizer.maskIdentifier(newFlowId));

            return Response.ok(Map.of(
                    "status", "reset-ok",
                    "reasonCode", SSIReasonCode.RESET_OK,
                    "flowId", newFlowId,
                    "previousStatus", previousStatus != null ? previousStatus : "none",
                    "message", "SSI flow reset successfully. Ready to retry.",
                    "nextStep", "poll",
                    "recoverable", true
            ))
                    .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                    .header("Pragma", "no-cache")
                    .header("Expires", "0")
                    .build();

        } catch (Exception e) {
            LOGGER.error("[MyResourceProvider] Error in /retry endpoint: " + LogSanitizer.redact(e.getMessage()));
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of(
                            "status", "error",
                            "reasonCode", SSIReasonCode.INTERNAL_ERROR,
                            "message", "Failed to reset SSI flow",
                            "recoverable", false
                    ))
                    .header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
                    .header("Pragma", "no-cache")
                    .header("Expires", "0")
                    .build();
        }
    }

    /**
     * Checks authentication and logs access attempts.
     *
     * <p>In soft mode (default), returns null for unauthenticated requests instead
     * of throwing an exception. This allows for transitional deployment where
     * authentication is recommended but not enforced.
     *
     * @return AuthResult if authenticated, null otherwise (in soft mode)
     */
    private AuthenticationManager.AuthResult checkAuthWithLogging() {
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (auth == null) {
            if (AUTH_SOFT_MODE) {
                LOGGER.debug("[MyResourceProvider] Bearer token authentication failed (soft mode)");
            } else {
                LOGGER.warn("[MyResourceProvider] Bearer token authentication failed");
            }
        } else {
            LOGGER.debug("[MyResourceProvider] Bearer token authentication successful for user: " + LogSanitizer.maskIdentifier(auth.getUser().getUsername()));
        }
        return auth;
    }

    /**
     * Builds a proxy URL for QR code generation through the Keycloak server.
     *
     * <p>This allows QR codes to be served from the same origin as the authentication
     * page, avoiding CORS issues and enabling the use of the /qr endpoint.
     *
     * @param data the data to encode in the QR code
     * @return a relative URL to the Keycloak QR code endpoint, or empty string if data is null/blank
     */
    private String buildQrProxyUrl(String data) {
        if (data == null || data.isBlank()) {
            return "";
        }
        String realmName = session.getContext().getRealm() != null ? session.getContext().getRealm().getName() : "";
        return "/realms/" + realmName + "/custom-resource/qr?data=" + URLEncoder.encode(data, StandardCharsets.UTF_8);
    }
}
