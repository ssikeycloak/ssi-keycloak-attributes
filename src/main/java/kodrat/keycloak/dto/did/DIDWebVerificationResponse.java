package kodrat.keycloak.dto.did;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Response DTO for DID Web verification.
 * Contains verification policy results and credential data.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class DIDWebVerificationResponse {

    /**
     * Policy verification results.
     */
    @JsonProperty("policyResults")
    private PolicyResults policyResults;

    /**
     * Returns the policy verification results.
     *
     * @return The PolicyResults object
     */
    public PolicyResults getPolicyResults() {
        return policyResults;
    }

    /**
     * Sets the policy verification results.
     *
     * @param policyResults The PolicyResults object to set
     */
    public void setPolicyResults(PolicyResults policyResults) {
        this.policyResults = policyResults;
    }

    /**
     * Extracts the credential subject from the verification response.
     *
     * @return An Optional containing the credential subject, or empty if not found
     */
    public Optional<JsonNode> getCredentialSubject() {
        if (policyResults == null || policyResults.getResults() == null) {
            return Optional.empty();
        }
        for (Result result : policyResults.getResults()) {
            if (result.getPolicyResults() != null) {
                for (Policy policy : result.getPolicyResults()) {
                    if (policy.getResult() != null && policy.getResult().getVc() != null) {
                        JsonNode credentialSubject = policy.getResult().getVc().getCredentialSubject();
                        if (credentialSubject != null && !credentialSubject.isMissingNode()) {
                            return Optional.of(credentialSubject);
                        }
                    }
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Checks if the response contains a credential subject.
     *
     * @return true if credential subject exists, false otherwise
     */
    public boolean hasCredentialSubject() {
        return getCredentialSubject().isPresent();
    }

    /**
     * Container for policy verification results.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class PolicyResults {
        /**
         * List of verification results.
         */
        @JsonProperty("results")
        private List<Result> results;

        /**
         * Returns the list of verification results.
         *
         * @return The list of Result objects
         */
        public List<Result> getResults() {
            return results;
        }

        /**
         * Sets the list of verification results.
         *
         * @param results The list of Result objects to set
         */
        public void setResults(List<Result> results) {
            this.results = results;
        }
    }

    /**
     * Individual verification result.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Result {
        /**
         * List of policy results.
         */
        @JsonProperty("policyResults")
        private List<Policy> policyResults;

        /**
         * Returns the list of policy results.
         *
         * @return The list of Policy objects
         */
        public List<Policy> getPolicyResults() {
            return policyResults;
        }

        /**
         * Sets the list of policy results.
         *
         * @param policyResults The list of Policy objects to set
         */
        public void setPolicyResults(List<Policy> policyResults) {
            this.policyResults = policyResults;
        }
    }

    /**
     * Policy verification result.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Policy {
        /**
         * The verifiable credential result.
         */
        @JsonProperty("result")
        private VerifiableCredentialResult result;

        /**
         * Returns the verifiable credential result.
         *
         * @return The VerifiableCredentialResult object
         */
        public VerifiableCredentialResult getResult() {
            return result;
        }

        /**
         * Sets the verifiable credential result.
         *
         * @param result The VerifiableCredentialResult object to set
         */
        public void setResult(VerifiableCredentialResult result) {
            this.result = result;
        }
    }

    /**
     * Container for verifiable credential result.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class VerifiableCredentialResult {
        /**
         * The verifiable credential.
         */
        @JsonProperty("vc")
        private VerifiableCredential vc;

        /**
         * Returns the verifiable credential.
         *
         * @return The VerifiableCredential object
         */
        public VerifiableCredential getVc() {
            return vc;
        }

        /**
         * Sets the verifiable credential.
         *
         * @param vc The VerifiableCredential object to set
         */
        public void setVc(VerifiableCredential vc) {
            this.vc = vc;
        }
    }

    /**
     * Verifiable credential data.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class VerifiableCredential {
        /**
         * The credential subject containing the claim data.
         */
        @JsonProperty("credentialSubject")
        private JsonNode credentialSubject;

        /**
         * Returns the credential subject.
         *
         * @return The credential subject as a JsonNode
         */
        public JsonNode getCredentialSubject() {
            return credentialSubject;
        }

        /**
         * Sets the credential subject.
         *
         * @param credentialSubject The credential subject to set
         */
        public void setCredentialSubject(JsonNode credentialSubject) {
            this.credentialSubject = credentialSubject;
        }
    }
}
