package kodrat.keycloak.dto.did;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * DTO representing a DID connection in the Sovrin framework.
 * Contains connection state and identifier information.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class DIDSovConnection {

    /**
     * Unique identifier for this connection.
     */
    @JsonProperty("connection_id")
    private String connectionId;

    /**
     * Current state of the connection.
     */
    @JsonProperty("state")
    private String state;

    /**
     * RFC23 state of the connection.
     */
    @JsonProperty("rfc23_state")
    private String rfc23State;

    /**
     * Message ID of the invitation that created this connection.
     */
    @JsonProperty("invitation_msg_id")
    private String invitationMsgId;

    /**
     * Returns the connection ID.
     *
     * @return The connection ID
     */
    public String getConnectionId() {
        return connectionId;
    }

    /**
     * Sets the connection ID.
     *
     * @param connectionId The connection ID to set
     */
    public void setConnectionId(String connectionId) {
        this.connectionId = connectionId;
    }

    /**
     * Returns the connection state.
     *
     * @return The connection state
     */
    public String getState() {
        return state;
    }

    /**
     * Sets the connection state.
     *
     * @param state The connection state to set
     */
    public void setState(String state) {
        this.state = state;
    }

    /**
     * Returns the RFC23 connection state.
     *
     * @return The RFC23 connection state
     */
    public String getRfc23State() {
        return rfc23State;
    }

    /**
     * Sets the RFC23 connection state.
     *
     * @param rfc23State The RFC23 connection state to set
     */
    public void setRfc23State(String rfc23State) {
        this.rfc23State = rfc23State;
    }

    /**
     * Returns the invitation message ID.
     *
     * @return The invitation message ID
     */
    public String getInvitationMsgId() {
        return invitationMsgId;
    }

    /**
     * Sets the invitation message ID.
     *
     * @param invitationMsgId The invitation message ID to set
     */
    public void setInvitationMsgId(String invitationMsgId) {
        this.invitationMsgId = invitationMsgId;
    }

    /**
     * Checks if the connection is active.
     *
     * @return true if active, false otherwise
     */
    public boolean isActive() {
        return "active".equalsIgnoreCase(state) && "completed".equalsIgnoreCase(rfc23State);
    }

    /**
     * Checks if the connection is pending.
     *
     * @return true if pending, false otherwise
     */
    public boolean isPending() {
        return "request".equalsIgnoreCase(state) ||
               "invitation".equalsIgnoreCase(state) ||
               "response".equalsIgnoreCase(state);
    }

    /**
     * Checks if the connection is in request state.
     *
     * @return true if in request state, false otherwise
     */
    public boolean isRequest() {
        return "request".equalsIgnoreCase(state);
    }

    /**
     * Checks if the RFC23 state is completed.
     *
     * @return true if RFC23 completed, false otherwise
     */
    public boolean isRfc23Completed() {
        return "completed".equalsIgnoreCase(rfc23State);
    }
}
