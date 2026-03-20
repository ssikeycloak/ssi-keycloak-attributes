package kodrat.keycloak.constant;

/**
 * Enumeration representing the various states of an SSI (Self-Sovereign Identity) authentication flow.
 */
public enum SSIStatus {
    /**
     * Initial state waiting for the flow to begin.
     */
    WAITING("waiting"),

    /**
     * Waiting for a DID connection to be established.
     */
    WAITING_CONNECTION("waiting-connection"),

    /**
     * Waiting for a proof request to be processed.
     */
    WAITING_PROOF("waiting-proof"),

    /**
     * Waiting for a presentation to be received from the holder.
     */
    WAITING_PRESENTATION("waiting-presentation"),

    /**
     * Proof request has been sent to the holder.
     */
    PROOF_REQUESTED("proof-requested"),

    /**
     * DID connection has been successfully established.
     */
    CONNECTED("connected"),

    /**
     * Currently verifying the presentation or credentials.
     */
    VERIFYING("verifying"),

    /**
     * Authentication flow completed successfully.
     */
    DONE("done"),

    /**
     * Authentication flow failed due to invalid data or credentials.
     */
    INVALID("invalid"),

    /**
     * Authentication flow failed due to an error.
     */
    FAILED("failed");

    /**
     * String representation of the status value.
     */
    private final String value;

    /**
     * Constructs an SSIStatus with the given string value.
     *
     * @param value The string representation of this status
     */
    SSIStatus(String value) {
        this.value = value;
    }

    /**
     * Returns the string value of this status.
     *
     * @return The string representation of this status
     */
    public String getValue() {
        return value;
    }

    /**
     * Parses a string value and returns the corresponding SSIStatus.
     *
     * @param value The string value to parse
     * @return The matching SSIStatus
     * @throws IllegalArgumentException if no matching status is found
     */
    public static SSIStatus fromValue(String value) {
        for (SSIStatus status : SSIStatus.values()) {
            if (status.value.equalsIgnoreCase(value)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown SSI status: " + value);
    }

    /**
     * Checks if this status is a terminal state (DONE, INVALID, or FAILED).
     *
     * @return true if this is a terminal state, false otherwise
     */
    public boolean isTerminal() {
        return this == DONE || this == INVALID || this == FAILED;
    }
}
