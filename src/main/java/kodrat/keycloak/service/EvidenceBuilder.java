package kodrat.keycloak.service;

import com.fasterxml.jackson.databind.JsonNode;
import kodrat.keycloak.dto.did.DIDSovProofResponse;
import kodrat.keycloak.util.LogSanitizer;

import java.time.Instant;
import java.util.*;
import java.util.logging.Logger;

/**
 * Utility service for building OpenID4VC-compliant evidence structures for audit trails.
 *
 * <p>Evidence provides verifiable information about the credential verification process,
 * following the OpenID4VC evidence specification. This allows relying parties to
 * understand how and when credentials were verified.
 *
 * <h2>Evidence Structure</h2>
 * <p>Each evidence item contains:
 * <table border="1">
 *   <caption>Evidence Fields</caption>
 *   <tr><th>Field</th><th>Type</th><th>Description</th></tr>
 *   <tr><td>{@code type}</td><td>String</td><td>Evidence type (typically "document")</td></tr>
 *   <tr><td>{@code method}</td><td>String</td><td>Verification method (jwt_vp, didcomm/present-proof, openid4vc)</td></tr>
 *   <tr><td>{@code time}</td><td>String</td><td>ISO 8601 timestamp of verification</td></tr>
 *   <tr><td>{@code document_details}</td><td>Object</td><td>Information about the verified document</td></tr>
 * </table>
 *
 * <h2>Document Details Structure</h2>
 * <p>The document_details object contains:
 * <table border="1">
 *   <caption>Document Details Fields</caption>
 *   <tr><th>Field</th><th>Type</th><th>Description</th></tr>
 *   <tr><td>{@code type}</td><td>String</td><td>Document type (identity_card, VerifiableDiploma, etc.)</td></tr>
 *   <tr><td>{@code issuer}</td><td>Object</td><td>Issuer information with name and country</td></tr>
 * </table>
 *
 * <h2>Supported Verification Methods</h2>
 * <ul>
 *   <li><strong>jwt_vp:</strong> JSON Web Token Verifiable Presentation (did:web)</li>
 *   <li><strong>didcomm/present-proof:</strong> Aries Present Proof protocol (did:sov)</li>
 *   <li><strong>openid4vc/verification:</strong> OpenID4VC verification (fallback)</li>
 * </ul>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * // For did:web verification
 * JsonNode policyResults = responseNode.path("policyResults");
 * List<Map<String, Object>> evidence = EvidenceBuilder.buildFromDidWeb(policyResults);
 *
 * // For did:sov verification
 * DIDSovProofResponse response = ...;
 * List<Map<String, Object>> evidence = EvidenceBuilder.buildFromSovrin(response);
 *
 * // Fallback when policy results unavailable
 * JsonNode credentialSubject = ...;
 * Map<String, Object> evidence = EvidenceBuilder.buildFallbackEvidence(credentialSubject);
 * }</pre>
 *
 * <h2>Thread Safety</h2>
 * <p>This class is stateless and all methods are static. It is safe to call from
 * multiple threads concurrently.
 *
 * @see CredentialAttributeExtractor
 * @see AttributeUtil
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public final class EvidenceBuilder {
    
    private static final Logger LOGGER = Logger.getLogger(EvidenceBuilder.class.getName());
    
    /**
     * Private constructor to prevent instantiation.
     * This is a utility class with only static methods.
     */
    private EvidenceBuilder() {}

    /**
     * Builds evidence from a DID Web (OpenID4VC) verification response.
     *
     * <p>Extracts credential information from the policy results structure:
     * <pre>
     * policyResults: {
     *   results: [{
     *     policyResults: [{
     *       result: {
     *         vc: { ... },
     *         issuanceDate: "..."
     *       }
     *     }]
     *   }]
     * }
     * </pre>
     *
     * <p>Evidence items are created for each verified credential found in the
     * policy results, extracting:
     * <ul>
     *   <li>Document type from VC type array</li>
     *   <li>Issuer from credential subject ID</li>
     *   <li>Verification time from issuance date</li>
     * </ul>
     *
     * @param policyResultsNode the policy results node from the verification response
     * @return a list of evidence items; empty list if no valid credentials found
     */
    public static List<Map<String, Object>> buildFromDidWeb(JsonNode policyResultsNode) {
        List<Map<String, Object>> evidenceList = new ArrayList<>();
        try {
            JsonNode resultsNode = policyResultsNode.path("results");
            if (!resultsNode.isArray() || resultsNode.isEmpty()) {
                return evidenceList;
            }
            
            for (JsonNode result : resultsNode) {
                JsonNode policyArray = result.path("policyResults");
                if (!policyArray.isArray()) continue;
                
                for (JsonNode policy : policyArray) {
                    JsonNode resultNode = policy.path("result");
                    JsonNode vcNode = resultNode.path("vc");
                    if (vcNode.isMissingNode()) continue;

                    String issuanceDate = resultNode.path("issuanceDate").asText(null);
                    if (issuanceDate == null || issuanceDate.isBlank()) {
                        issuanceDate = vcNode.path("issuanceDate").asText(null);
                    }

                    String docType = extractDocumentType(vcNode);
                    String issuerName = vcNode.path("credentialSubject").path("id").asText("");

                    Map<String, Object> documentDetails = new HashMap<>();
                    documentDetails.put("type", docType);
                    Map<String, Object> issuer = new HashMap<>();
                    issuer.put("name", issuerName);
                    documentDetails.put("issuer", issuer);

                    Map<String, Object> evidenceItem = new HashMap<>();
                    evidenceItem.put("type", "document");
                    evidenceItem.put("method", "jwt_vp");
                    evidenceItem.put("time", issuanceDate != null ? issuanceDate : Instant.now().toString());
                    evidenceItem.put("document_details", documentDetails);
                    evidenceList.add(evidenceItem);
                }
            }
        } catch (Exception e) {
            LOGGER.warning("[EvidenceBuilder] Failed to build evidence: " + LogSanitizer.redact(e.getMessage()));
        }
        return evidenceList;
    }

    /**
     * Builds evidence from a DID Sov (Indy/Aries) verification response.
     *
     * <p>Extracts credential information from the ACA-Py present-proof response:
     * <ul>
     *   <li>Issuer name from the first part of the schema ID</li>
     *   <li>Verification time from the updated_at timestamp</li>
     *   <li>Document type set to "identity_card"</li>
     * </ul>
     *
     * <p>Schema ID format: {@code did:sov:{issuer}:{schema_name}:{version}}
     *
     * @param response the presentation proof response from ACA-Py
     * @return a list containing one evidence item; empty list if no identifier found
     */
    public static List<Map<String, Object>> buildFromSovrin(DIDSovProofResponse response) {
        List<Map<String, Object>> evidenceList = new ArrayList<>();
        try {
            Optional<DIDSovProofResponse.Identifier> firstId = response.getFirstIdentifier();
            if (firstId.isEmpty()) {
                return evidenceList;
            }
            
            String schemaId = firstId.get().getSchemaId();
            String updatedAt = response.getUpdatedAt();
            String[] schemaParts = schemaId != null ? schemaId.split(":") : new String[0];
            String issuerName = schemaParts.length > 0 ? schemaParts[0] : "unknown";

            Map<String, Object> evidenceItem = new HashMap<>();
            evidenceItem.put("type", "document");
            evidenceItem.put("method", "didcomm/present-proof");
            evidenceItem.put("time", updatedAt != null ? updatedAt : Instant.now().toString());

            Map<String, Object> docDetails = new HashMap<>();
            docDetails.put("type", "identity_card");
            Map<String, String> issuer = new HashMap<>();
            issuer.put("name", issuerName);
            issuer.put("country", "ID");
            docDetails.put("issuer", issuer);
            evidenceItem.put("document_details", docDetails);
            evidenceList.add(evidenceItem);
        } catch (Exception e) {
            LOGGER.warning("[EvidenceBuilder] Failed to build Sovrin evidence: " + LogSanitizer.redact(e.getMessage()));
        }
        return evidenceList;
    }

    /**
     * Builds fallback evidence when policy results are not available.
     *
     * <p>Use this method when the verification response doesn't contain structured
     * policy results but credential subject information is available directly.
     *
     * <p>The fallback evidence includes:
     * <ul>
     *   <li>Type: "document"</li>
     *   <li>Method: "openid4vc/verification"</li>
     *   <li>Time: Current timestamp</li>
     *   <li>Document type: "verifiable_credential"</li>
     *   <li>Issuer: From credential subject ID</li>
     * </ul>
     *
     * @param credentialSubject the credential subject JSON node
     * @return a single evidence item map
     */
    public static Map<String, Object> buildFallbackEvidence(JsonNode credentialSubject) {
        Map<String, Object> evidenceItem = new HashMap<>();
        evidenceItem.put("type", "document");
        evidenceItem.put("method", "openid4vc/verification");
        evidenceItem.put("time", Instant.now().toString());

        Map<String, Object> documentDetails = new HashMap<>();
        documentDetails.put("type", "verifiable_credential");

        String issuerName = credentialSubject.path("id").asText("did:web");
        Map<String, String> issuer = new HashMap<>();
        issuer.put("name", issuerName);
        issuer.put("country", "ID");

        documentDetails.put("issuer", issuer);
        evidenceItem.put("document_details", documentDetails);
        return evidenceItem;
    }

    /**
     * Extracts the document type from a verifiable credential node.
     *
     * <p>VC type is typically an array where the second element is the specific
     * credential type (e.g., ["VerifiableCredential", "VerifiableDiploma"]).
     *
     * @param vcNode the verifiable credential JSON node
     * @return the document type string, or "identity_document" as default
     */
    private static String extractDocumentType(JsonNode vcNode) {
        String docType = "identity_document";
        JsonNode vcTypeArray = vcNode.path("type");
        if (vcTypeArray.isArray() && vcTypeArray.size() > 1) {
            docType = vcTypeArray.get(1).asText();
        } else if (vcTypeArray.isArray() && vcTypeArray.size() == 1) {
            docType = vcTypeArray.get(0).asText();
        }
        return docType;
    }
}
