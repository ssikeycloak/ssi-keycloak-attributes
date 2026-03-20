package kodrat.keycloak.dto.did;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

/**
 * Response DTO for creating a DID connection invitation.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CreateInvitationResponse {

    /**
     * The URL for the invitation that can be used to establish a connection.
     */
    @JsonProperty("invitation_url")
    private String invitationUrl;

    /**
     * The message ID of the invitation message.
     */
    @JsonProperty("invi_msg_id")
    private String inviMsgId;

    /**
     * The invitation object containing services and protocols.
     */
    @JsonProperty("invitation")
    private Invitation invitation;

    /**
     * Returns the invitation URL.
     *
     * @return The invitation URL
     */
    public String getInvitationUrl() {
        return invitationUrl;
    }

    /**
     * Sets the invitation URL.
     *
     * @param invitationUrl The invitation URL to set
     */
    public void setInvitationUrl(String invitationUrl) {
        this.invitationUrl = invitationUrl;
    }

    /**
     * Returns the invitation message ID.
     *
     * @return The invitation message ID
     */
    public String getInviMsgId() {
        return inviMsgId;
    }

    /**
     * Sets the invitation message ID.
     *
     * @param inviMsgId The invitation message ID to set
     */
    public void setInviMsgId(String inviMsgId) {
        this.inviMsgId = inviMsgId;
    }

    /**
     * Returns the invitation object.
     *
     * @return The invitation object
     */
    public Invitation getInvitation() {
        return invitation;
    }

    /**
     * Sets the invitation object.
     *
     * @param invitation The invitation object to set
     */
    public void setInvitation(Invitation invitation) {
        this.invitation = invitation;
    }

    /**
     * Extracts the resolvable DID from the invitation services.
     * This DID is used for connection reuse.
     *
     * @return The resolvable DID (e.g., did:peer:2...), or null if not available
     */
    public String getResolvableDid() {
        if (invitation != null && invitation.getServices() != null && !invitation.getServices().isEmpty()) {
            // First service entry is typically the resolvable DID
            Object service = invitation.getServices().get(0);
            if (service instanceof String) {
                String did = (String) service;
                // Only return if it looks like a resolvable DID (did:peer:2 or did:peer:4)
                if (did.startsWith("did:peer:2") || did.startsWith("did:peer:4")) {
                    return did;
                }
            }
        }
        return null;
    }

    /**
     * Inner class representing the invitation object.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Invitation {

        @JsonProperty("services")
        private List<Object> services;

        @JsonProperty("handshake_protocols")
        private List<String> handshakeProtocols;

        public List<Object> getServices() {
            return services;
        }

        public void setServices(List<Object> services) {
            this.services = services;
        }

        public List<String> getHandshakeProtocols() {
            return handshakeProtocols;
        }

        public void setHandshakeProtocols(List<String> handshakeProtocols) {
            this.handshakeProtocols = handshakeProtocols;
        }
    }
}
