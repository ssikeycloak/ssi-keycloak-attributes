package kodrat.keycloak.service.flow;

import kodrat.keycloak.api.DIDMethod;
import kodrat.keycloak.api.SSIResult;
import kodrat.keycloak.constant.SSIStatus;
import kodrat.keycloak.util.LogSanitizer;
import org.jboss.logging.Logger;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.HashMap;
import java.util.Map;

import static kodrat.keycloak.service.flow.SSIFlowResult.FlowStatus;

/**
 * Central orchestrator for SSI authentication flow.
 * Eliminates duplication between authenticator and REST API paths
 * by providing a unified flow execution engine.
 */
public class SSIFlowOrchestrator {

    private static final Logger LOGGER = Logger.getLogger(SSIFlowOrchestrator.class);

    public static final String NOTE_SSI_FLOW_ID = "ssi_flow_id";
    public static final String NOTE_SSI_STATUS = "ssi_status";
    public static final String NOTE_INVITATION_URL = "invitation_url";
    public static final String NOTE_CONNECTION_ID = "connection_id";
    public static final String NOTE_PRES_EX_ID = "pres_ex_id";
    public static final String NOTE_INVI_MSG_ID = "invi_msg_id";
    public static final String NOTE_VERIFIED_CLAIMS = "verified_claims";

    private final SSIFlowContextAdapter context;

    public SSIFlowOrchestrator(SSIFlowContextAdapter context) {
        this.context = context;
    }

    /**
     * Executes the complete SSI authentication flow.
     * Steps: Connection -> Proof Request -> Presentation -> Verification
     */
    public SSIFlowResult executeFlow() {
        LOGGER.info("[SSIFlowOrchestrator] Starting SSI flow execution");

        try {
            SSIFlowResult connectionResult = checkConnection();
            if (!connectionResult.isSuccess()) {
                LOGGER.info("[SSIFlowOrchestrator] Connection not established yet");
                return connectionResult;
            }

            String currentStatus = context.getAuthNote(NOTE_SSI_STATUS);
            if (!SSIStatus.PROOF_REQUESTED.getValue().equals(currentStatus)) {
                SSIFlowResult proofResult = sendProofRequest();
                if (!proofResult.isSuccess()) {
                    LOGGER.info("[SSIFlowOrchestrator] Proof request pending or failed");
                    return proofResult;
                }
            }

            SSIFlowResult presentationResult = checkPresentation();
            if (!presentationResult.isSuccess()) {
                LOGGER.info("[SSIFlowOrchestrator] Waiting for presentation");
                return presentationResult;
            }

            SSIFlowResult verificationResult = verifyPresentation();
            LOGGER.info("[SSIFlowOrchestrator] Flow execution completed with status: " + verificationResult.getStatus());
            return verificationResult;

        } catch (Exception e) {
            LOGGER.error("[SSIFlowOrchestrator] Flow execution error: " + LogSanitizer.redact(e.getMessage()), e);
            return SSIFlowResult.failure(FlowStatus.ERROR, "Flow execution failed: " + e.getMessage(), e);
        }
    }

    private SSIFlowResult checkConnection() {
        AuthenticationSessionModel session = context.getAuthenticationSession();
        DIDMethod method = context.getDIDMethod();

        LOGGER.info("[SSIFlowOrchestrator] Step 1: Checking connection");

        if (method.isConnectionEstablished(session)) {
            String connectionId = context.getAuthNote(NOTE_CONNECTION_ID);
            LOGGER.info("[SSIFlowOrchestrator] Connection established: " + LogSanitizer.maskIdentifier(connectionId));

            Map<String, Object> data = new HashMap<>();
            data.put("connectionId", connectionId);
            data.put("qrCodeUrl", "");

            return SSIFlowResult.success(FlowStatus.CONNECTED, data, "Connection established");
        }

        String invitationUrl = context.getAuthNote(NOTE_INVITATION_URL);
        if (invitationUrl == null || invitationUrl.isEmpty()) {
            invitationUrl = "";
        }
        String qrCodeUrl = method.generateQRCode(invitationUrl);

        context.setAuthNote(NOTE_SSI_STATUS, SSIStatus.WAITING_CONNECTION.getValue());

        Map<String, Object> data = new HashMap<>();
        data.put("qrCodeUrl", qrCodeUrl);
        data.put("status", SSIStatus.WAITING_CONNECTION.getValue());

        return failureWithData(FlowStatus.WAITING_CONNECTION, "Waiting for wallet connection", data);
    }

    private SSIFlowResult sendProofRequest() {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        DIDMethod method = context.getDIDMethod();

        LOGGER.info("[SSIFlowOrchestrator] Step 2: Sending proof request");

        SSIResult result = method.sendProofRequest(authSession);

        if (result.isDone()) {
            context.setAuthNote(NOTE_SSI_STATUS, SSIStatus.PROOF_REQUESTED.getValue());
            LOGGER.info("[SSIFlowOrchestrator] Proof request sent successfully");
            return SSIFlowResult.success(FlowStatus.PROOF_REQUESTED, "Proof request sent");
        } else {
            context.setAuthNote(NOTE_SSI_STATUS, SSIStatus.WAITING_PROOF.getValue());
            LOGGER.info("[SSIFlowOrchestrator] Proof request pending");
            return SSIFlowResult.failure(FlowStatus.WAITING_PROOF, "Proof request pending: " + result.getMessage());
        }
    }

    private SSIFlowResult checkPresentation() {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        DIDMethod method = context.getDIDMethod();

        LOGGER.info("[SSIFlowOrchestrator] Step 3: Checking presentation");

        if (method.hasReceivedPresentation(authSession)) {
            LOGGER.info("[SSIFlowOrchestrator] Presentation received");
            return SSIFlowResult.success(FlowStatus.WAITING_PRESENTATION, "Presentation received");
        }

        context.setAuthNote(NOTE_SSI_STATUS, SSIStatus.WAITING_PRESENTATION.getValue());
        return SSIFlowResult.failure(FlowStatus.WAITING_PRESENTATION, "Waiting for credential presentation");
    }

    private SSIFlowResult verifyPresentation() {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        DIDMethod method = context.getDIDMethod();

        LOGGER.info("[SSIFlowOrchestrator] Step 4: Verifying presentation");

        boolean verified = method.verifyPresentation(authSession);

        if (verified) {
            context.setAuthNote(NOTE_SSI_STATUS, SSIStatus.DONE.getValue());

            context.removeAuthNote(NOTE_INVI_MSG_ID);
            context.removeAuthNote(NOTE_PRES_EX_ID);
            context.removeAuthNote(NOTE_SSI_FLOW_ID);

            LOGGER.info("[SSIFlowOrchestrator] Verification successful");
            return SSIFlowResult.success(FlowStatus.VERIFIED, "Verification successful");
        } else {
            context.setAuthNote(NOTE_SSI_STATUS, SSIStatus.INVALID.getValue());
            LOGGER.warn("[SSIFlowOrchestrator] Verification failed");
            return SSIFlowResult.failure(FlowStatus.FAILED, "Verification failed");
        }
    }

    public SSIStatus getCurrentStatus() {
        String statusStr = context.getAuthNote(NOTE_SSI_STATUS);
        if (statusStr == null || statusStr.isEmpty()) {
            return SSIStatus.WAITING;
        }
        try {
            return SSIStatus.fromValue(statusStr);
        } catch (IllegalArgumentException e) {
            LOGGER.warn("[SSIFlowOrchestrator] Unknown status: " + statusStr);
            return SSIStatus.WAITING;
        }
    }

    private static SSIFlowResult failureWithData(FlowStatus status, String message, Map<String, Object> data) {
        return new SSIFlowResult.Builder()
                .success(false)
                .status(status)
                .message(message)
                .data(data)
                .build();
    }
}
