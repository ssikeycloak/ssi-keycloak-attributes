package kodrat.keycloak.config;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.AuthenticatorConfigModel;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public final class ConfigurationValidator {
    private static final Logger LOGGER = Logger.getLogger(ConfigurationValidator.class.getName());
    
    private static final Pattern URL_PATTERN = Pattern.compile("^https?://[\\w.-]+(:\\d+)?(/.*)?$");
    private static final Pattern DID_PATTERN = Pattern.compile("^did:(web|sov|peer|key):.+$");
    private static final int MAX_TIMEOUT_SECONDS = 300;
    private static final int MIN_TIMEOUT_SECONDS = 1;
    
    private ConfigurationValidator() {}
    
    public static ValidationResult validate(AuthenticationFlowContext context) {
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        
        if (context == null) {
            errors.add("AuthenticationFlowContext is null");
            return new ValidationResult(false, errors, warnings);
        }
        
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        if (config == null) {
            errors.add("Authenticator configuration is missing");
            return new ValidationResult(false, errors, warnings);
        }
        
        Map<String, String> configMap = config.getConfig();
        if (configMap == null || configMap.isEmpty()) {
            errors.add("Authenticator configuration is empty");
            return new ValidationResult(false, errors, warnings);
        }
        
        validateEndpoint(configMap, errors, warnings);
        validateDidMethod(configMap, errors, warnings);
        validateSchemaConfig(configMap, errors, warnings);
        validateTimeouts(configMap, errors, warnings);
        validateDidIdentifiers(configMap, errors, warnings);
        
        boolean valid = errors.isEmpty();
        
        if (valid) {
            LOGGER.info("[ConfigurationValidator] Configuration validation passed with " + warnings.size() + " warnings");
        } else {
            LOGGER.severe("[ConfigurationValidator] Configuration validation failed with " + errors.size() + " errors");
        }
        
        return new ValidationResult(valid, errors, warnings);
    }
    
    private static void validateEndpoint(Map<String, String> config, List<String> errors, List<String> warnings) {
        String endpoint = config.get("ssi_endpoint");
        if (endpoint == null || endpoint.isBlank()) {
            errors.add("SSI endpoint is not configured");
            return;
        }
        
        endpoint = endpoint.trim();
        if (!URL_PATTERN.matcher(endpoint).matches()) {
            errors.add("SSI endpoint URL format is invalid: " + maskUrl(endpoint));
            return;
        }
        
        if (endpoint.startsWith("http://") && !endpoint.contains("localhost") && !endpoint.contains("127.0.0.1")) {
            warnings.add("SSI endpoint uses HTTP (not HTTPS) - not recommended for production");
        }
        
        try {
            URI uri = URI.create(endpoint);
            if (uri.getHost() == null || uri.getHost().isBlank()) {
                errors.add("SSI endpoint URL has no host");
            }
        } catch (Exception e) {
            errors.add("SSI endpoint URL parsing failed: " + e.getMessage());
        }
    }
    
    private static void validateDidMethod(Map<String, String> config, List<String> errors, List<String> warnings) {
        String didMethod = config.get("did_method");
        if (didMethod == null || didMethod.isBlank()) {
            warnings.add("DID method not specified, will use default");
            return;
        }
        
        didMethod = didMethod.trim().toLowerCase();
        if (!List.of("web", "sov").contains(didMethod)) {
            errors.add("Invalid DID method: " + didMethod + ". Must be 'web' or 'sov'");
        }
    }
    
    private static void validateSchemaConfig(Map<String, String> config, List<String> errors, List<String> warnings) {
        String schemaId = config.get("schema_id");
        String schemaName = config.get("schema_name");
        
        if (schemaId == null || schemaId.isBlank()) {
            if (schemaName == null || schemaName.isBlank()) {
                warnings.add("No schema configuration (schema_id or schema_name) - may affect credential verification");
            }
        }
        
        String requestedCredential = config.get("requested_credential");
        if (requestedCredential != null && !requestedCredential.isBlank()) {
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                mapper.readTree(requestedCredential);
            } catch (Exception e) {
                errors.add("requested_credential is not valid JSON: " + e.getMessage());
            }
        }
    }
    
    private static void validateTimeouts(Map<String, String> config, List<String> errors, List<String> warnings) {
        String connectionTimeout = config.get("connection_timeout_seconds");
        if (connectionTimeout != null && !connectionTimeout.isBlank()) {
            try {
                int timeout = Integer.parseInt(connectionTimeout.trim());
                if (timeout < MIN_TIMEOUT_SECONDS || timeout > MAX_TIMEOUT_SECONDS) {
                    errors.add("connection_timeout_seconds must be between " + MIN_TIMEOUT_SECONDS + " and " + MAX_TIMEOUT_SECONDS);
                }
            } catch (NumberFormatException e) {
                errors.add("connection_timeout_seconds is not a valid number: " + connectionTimeout);
            }
        }
        
        String requestTimeout = config.get("request_timeout_seconds");
        if (requestTimeout != null && !requestTimeout.isBlank()) {
            try {
                int timeout = Integer.parseInt(requestTimeout.trim());
                if (timeout < MIN_TIMEOUT_SECONDS || timeout > MAX_TIMEOUT_SECONDS) {
                    errors.add("request_timeout_seconds must be between " + MIN_TIMEOUT_SECONDS + " and " + MAX_TIMEOUT_SECONDS);
                }
            } catch (NumberFormatException e) {
                errors.add("request_timeout_seconds is not a valid number: " + requestTimeout);
            }
        }
    }
    
    private static void validateDidIdentifiers(Map<String, String> config, List<String> errors, List<String> warnings) {
        String subjectDid = config.get("subject_did");
        if (subjectDid != null && !subjectDid.isBlank()) {
            if (!DID_PATTERN.matcher(subjectDid.trim()).matches()) {
                warnings.add("subject_did may not be a valid DID format: " + maskDid(subjectDid));
            }
        }
        
        String issuerDid = config.get("issuer_did");
        if (issuerDid != null && !issuerDid.isBlank()) {
            if (!DID_PATTERN.matcher(issuerDid.trim()).matches()) {
                warnings.add("issuer_did may not be a valid DID format: " + maskDid(issuerDid));
            }
        }
    }
    
    private static String maskUrl(String url) {
        if (url == null || url.length() < 20) {
            return "***";
        }
        return url.substring(0, 10) + "***" + url.substring(url.length() - 10);
    }
    
    private static String maskDid(String did) {
        if (did == null || did.length() < 20) {
            return "***";
        }
        return did.substring(0, 10) + "***" + did.substring(did.length() - 10);
    }
    
    public static class ValidationResult {
        private final boolean valid;
        private final List<String> errors;
        private final List<String> warnings;
        
        public ValidationResult(boolean valid, List<String> errors, List<String> warnings) {
            this.valid = valid;
            this.errors = errors != null ? new ArrayList<>(errors) : new ArrayList<>();
            this.warnings = warnings != null ? new ArrayList<>(warnings) : new ArrayList<>();
        }
        
        public boolean isValid() {
            return valid;
        }
        
        public List<String> getErrors() {
            return new ArrayList<>(errors);
        }
        
        public List<String> getWarnings() {
            return new ArrayList<>(warnings);
        }
        
        public String getErrorMessage() {
            return String.join("; ", errors);
        }
        
        public String getWarningMessage() {
            return String.join("; ", warnings);
        }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("ValidationResult{valid=").append(valid);
            if (!errors.isEmpty()) {
                sb.append(", errors=").append(errors);
            }
            if (!warnings.isEmpty()) {
                sb.append(", warnings=").append(warnings);
            }
            sb.append("}");
            return sb.toString();
        }
    }
}
