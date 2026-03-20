package kodrat.keycloak.dto.did;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Response DTO containing a list of DID connections.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ConnectionsResponse {

    /**
     * List of connection results.
     */
    @JsonProperty("results")
    private List<DIDSovConnection> results;

    /**
     * Returns the list of connections.
     *
     * @return The list of DID connections
     */
    public List<DIDSovConnection> getResults() {
        return results;
    }

    /**
     * Sets the list of connections.
     *
     * @param results The list of DID connections to set
     */
    public void setResults(List<DIDSovConnection> results) {
        this.results = results;
    }
}
