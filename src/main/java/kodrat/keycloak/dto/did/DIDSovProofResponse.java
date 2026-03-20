package kodrat.keycloak.dto.did;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Response DTO for proof verification in the Sovrin DID framework.
 * Contains proof presentation data and verification results.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class DIDSovProofResponse {

    /**
     * The current state of the proof verification.
     */
    @JsonProperty("state")
    private String state;

    /**
     * Whether the proof has been verified (as a string).
     */
    @JsonProperty("verified")
    private String verified;

    /**
     * Presentation data organized by format.
     */
    @JsonProperty("by_format")
    private ByFormat byFormat;

    /**
     * Timestamp of the last update.
     */
    @JsonProperty("updated_at")
    private String updatedAt;

    /**
     * Returns the current state of the proof verification.
     *
     * @return The proof verification state
     */
    public String getState() {
        return state;
    }

    /**
     * Sets the state of the proof verification.
     *
     * @param state The state to set
     */
    public void setState(String state) {
        this.state = state;
    }

    /**
     * Returns whether the proof has been verified.
     *
     * @return The verification status as a string
     */
    public String getVerified() {
        return verified;
    }

    /**
     * Sets the verification status.
     *
     * @param verified The verification status to set
     */
    public void setVerified(String verified) {
        this.verified = verified;
    }

    /**
     * Returns the presentation data organized by format.
     *
     * @return The ByFormat object containing presentation data
     */
    public ByFormat getByFormat() {
        return byFormat;
    }

    /**
     * Sets the presentation data organized by format.
     *
     * @param byFormat The ByFormat object to set
     */
    public void setByFormat(ByFormat byFormat) {
        this.byFormat = byFormat;
    }

    /**
     * Returns the timestamp of the last update.
     *
     * @return The update timestamp
     */
    public String getUpdatedAt() {
        return updatedAt;
    }

    /**
     * Sets the timestamp of the last update.
     *
     * @param updatedAt The timestamp to set
     */
    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * Checks if the proof has been successfully verified.
     *
     * @return true if verified, false otherwise
     */
    public boolean isVerified() {
        return "true".equalsIgnoreCase(verified) &&
               ("done".equalsIgnoreCase(state) || "verified".equalsIgnoreCase(state) ||
                ("deleted".equalsIgnoreCase(state) && "true".equalsIgnoreCase(verified)));
    }

    /**
     * Checks if the presentation has been received.
     *
     * @return true if presentation received, false otherwise
     */
    public boolean isPresentationReceived() {
        return "presentation-received".equalsIgnoreCase(state);
    }

    /**
     * Checks if the verification is complete.
     *
     * @return true if done, false otherwise
     */
    public boolean isDone() {
        return "done".equalsIgnoreCase(state);
    }

    /**
     * Checks if the state is verified.
     *
     * @return true if in verified state, false otherwise
     */
    public boolean isVerifiedState() {
        return "verified".equalsIgnoreCase(state);
    }

    /**
     * Extracts the revealed attributes from the proof presentation.
     *
     * @return A map of attribute referents to their values
     */
    public Map<String, String> getRevealedAttributes() {
        Map<String, String> attributes = new HashMap<>();
        if (byFormat == null || byFormat.getPres() == null || byFormat.getPres().getIndy() == null) {
            return attributes;
        }
        JsonNode revealedAttrsNode = byFormat.getPres().getIndy().getRequestedProof().getRevealedAttrs();
        if (revealedAttrsNode == null || !revealedAttrsNode.isObject()) {
            return attributes;
        }
        revealedAttrsNode.fields().forEachRemaining(entry -> {
            String referent = entry.getKey();
            JsonNode valueNode = entry.getValue();
            if (valueNode != null && valueNode.has("raw")) {
                String rawValue = valueNode.get("raw").asText();
                if (rawValue != null) {
                    attributes.put(referent, rawValue);
                }
            }
        });
        return attributes;
    }

    /**
     * Returns the list of credential identifiers.
     *
     * @return The list of identifiers
     */
    public List<Identifier> getIdentifiers() {
        if (byFormat == null || byFormat.getPres() == null || byFormat.getPres().getIndy() == null) {
            return new ArrayList<>();
        }
        List<Identifier> identifiers = byFormat.getPres().getIndy().getIdentifiers();
        return identifiers != null ? identifiers : new ArrayList<>();
    }

    /**
     * Returns the first credential identifier if available.
     *
     * @return An Optional containing the first identifier, or empty if none
     */
    public Optional<Identifier> getFirstIdentifier() {
        List<Identifier> identifiers = getIdentifiers();
        return identifiers.isEmpty() ? Optional.empty() : Optional.of(identifiers.get(0));
    }

    /**
     * Container for presentation data organized by format.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ByFormat {
        /**
         * The presentation data.
         */
        @JsonProperty("pres")
        private Pres pres;

        /**
         * Returns the presentation data.
         *
         * @return The Pres object
         */
        public Pres getPres() {
            return pres;
        }

        /**
         * Sets the presentation data.
         *
         * @param pres The Pres object to set
         */
        public void setPres(Pres pres) {
            this.pres = pres;
        }
    }

    /**
     * Presentation data container.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Pres {
        /**
         * Indy-specific presentation data.
         */
        @JsonProperty("indy")
        private Indy indy;

        /**
         * Returns the Indy presentation data.
         *
         * @return The Indy object
         */
        public Indy getIndy() {
            return indy;
        }

        /**
         * Sets the Indy presentation data.
         *
         * @param indy The Indy object to set
         */
        public void setIndy(Indy indy) {
            this.indy = indy;
        }
    }

    /**
     * Indy-specific presentation data.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Indy {
        /**
         * The requested proof information.
         */
        @JsonProperty("requested_proof")
        private RequestedProof requestedProof;

        /**
         * List of credential identifiers.
         */
        @JsonProperty("identifiers")
        private List<Identifier> identifiers;

        /**
         * Returns the requested proof information.
         *
         * @return The RequestedProof object
         */
        public RequestedProof getRequestedProof() {
            return requestedProof;
        }

        /**
         * Sets the requested proof information.
         *
         * @param requestedProof The RequestedProof object to set
         */
        public void setRequestedProof(RequestedProof requestedProof) {
            this.requestedProof = requestedProof;
        }

        /**
         * Returns the list of credential identifiers.
         *
         * @return The list of identifiers
         */
        public List<Identifier> getIdentifiers() {
            return identifiers;
        }

        /**
         * Sets the list of credential identifiers.
         *
         * @param identifiers The list of identifiers to set
         */
        public void setIdentifiers(List<Identifier> identifiers) {
            this.identifiers = identifiers;
        }
    }

    /**
     * Container for requested proof information.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class RequestedProof {
        /**
         * The revealed attributes from the proof.
         */
        @JsonProperty("revealed_attrs")
        private JsonNode revealedAttrs;

        /**
         * Returns the revealed attributes.
         *
         * @return The revealed attributes as a JsonNode
         */
        public JsonNode getRevealedAttrs() {
            return revealedAttrs;
        }

        /**
         * Sets the revealed attributes.
         *
         * @param revealedAttrs The revealed attributes to set
         */
        public void setRevealedAttrs(JsonNode revealedAttrs) {
            this.revealedAttrs = revealedAttrs;
        }
    }

    /**
     * Credential identifier information.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Identifier {
        /**
         * The schema ID of the credential.
         */
        @JsonProperty("schema_id")
        private String schemaId;

        /**
         * The credential definition ID.
         */
        @JsonProperty("cred_def_id")
        private String credDefId;

        /**
         * Returns the schema ID.
         *
         * @return The schema ID
         */
        public String getSchemaId() {
            return schemaId;
        }

        /**
         * Sets the schema ID.
         *
         * @param schemaId The schema ID to set
         */
        public void setSchemaId(String schemaId) {
            this.schemaId = schemaId;
        }

        /**
         * Returns the credential definition ID.
         *
         * @return The credential definition ID
         */
        public String getCredDefId() {
            return credDefId;
        }

        /**
         * Sets the credential definition ID.
         *
         * @param credDefId The credential definition ID to set
         */
        public void setCredDefId(String credDefId) {
            this.credDefId = credDefId;
        }
    }
}
