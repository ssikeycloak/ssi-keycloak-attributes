package kodrat.keycloak.config;

import java.util.Base64;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JwtUtils {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static JsonNode decodeJwtPayload(String jwtToken) throws Exception {
        String[] parts = jwtToken.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid JWT: must have at least 2 parts (header.payload)");
        }

        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
        return objectMapper.readTree(payload);
    }
}
