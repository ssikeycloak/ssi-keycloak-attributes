package kodrat.keycloak.service.flow;

import java.util.Map;

/**
 * Result object for SSI flow operations.
 * Immutable result containing status, data, and optional error information.
 */
public class SSIFlowResult {

    private final boolean success;
    private final FlowStatus status;
    private final Map<String, Object> data;
    private final String message;
    private final Throwable error;

    private SSIFlowResult(Builder builder) {
        this.success = builder.success;
        this.status = builder.status;
        this.data = builder.data != null ? Map.copyOf(builder.data) : Map.of();
        this.message = builder.message;
        this.error = builder.error;
    }

    /**
     * Creates a successful result.
     */
    public static SSIFlowResult success(FlowStatus status, Map<String, Object> data, String message) {
        return new Builder()
                .success(true)
                .status(status)
                .data(data)
                .message(message)
                .build();
    }

    /**
     * Creates a successful result with default empty data.
     */
    public static SSIFlowResult success(FlowStatus status, String message) {
        return success(status, Map.of(), message);
    }

    /**
     * Creates a failure result.
     */
    public static SSIFlowResult failure(FlowStatus status, String message, Throwable error) {
        return new Builder()
                .success(false)
                .status(status)
                .message(message)
                .error(error)
                .build();
    }

    /**
     * Creates a failure result without exception.
     */
    public static SSIFlowResult failure(FlowStatus status, String message) {
        return failure(status, message, null);
    }

    public boolean isSuccess() {
        return success;
    }

    public FlowStatus getStatus() {
        return status;
    }

    public Map<String, Object> getData() {
        return data;
    }

    public String getMessage() {
        return message;
    }

    public Throwable getError() {
        return error;
    }

    public boolean hasError() {
        return error != null;
    }

    @Override
    public String toString() {
        return "SSIFlowResult{" +
                "success=" + success +
                ", status=" + status +
                ", message='" + message + '\'' +
                ", hasError=" + hasError() +
                '}';
    }

    /**
     * Flow status enumeration representing the various states of SSI authentication flow.
     */
    public enum FlowStatus {
        WAITING_CONNECTION,
        WAITING_PROOF,
        WAITING_PRESENTATION,
        PROOF_REQUESTED,
        CONNECTED,
        VERIFYING,
        VERIFIED,
        FAILED,
        TIMEOUT,
        ERROR
    }

    public static class Builder {
        private boolean success;
        private FlowStatus status;
        private Map<String, Object> data;
        private String message;
        private Throwable error;

        public Builder success(boolean success) {
            this.success = success;
            return this;
        }

        public Builder status(FlowStatus status) {
            this.status = status;
            return this;
        }

        public Builder data(Map<String, Object> data) {
            this.data = data;
            return this;
        }

        public Builder message(String message) {
            this.message = message;
            return this;
        }

        public Builder error(Throwable error) {
            this.error = error;
            return this;
        }

        public SSIFlowResult build() {
            if (status == null) {
                throw new IllegalStateException("Status is required");
            }
            return new SSIFlowResult(this);
        }
    }
}
