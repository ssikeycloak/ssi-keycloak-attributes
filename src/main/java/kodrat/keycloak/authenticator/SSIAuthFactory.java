package kodrat.keycloak.authenticator;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@AutoService(AuthenticatorFactory.class)
public class SSIAuthFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "ssi-authenticator";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "SSI Authentication";
    }

    @Override
    public String getReferenceCategory() {
        return "ssi";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[]{
                AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public String getHelpText() {
        return "Validates credentials using Self-Sovereign Identity (SSI) with multiple DID methods.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> properties = new ArrayList<>();

        // DID Method
        ProviderConfigProperty didMethodProperty = new ProviderConfigProperty();
        didMethodProperty.setName("did_method");
        didMethodProperty.setLabel("DID Method");
        didMethodProperty.setType(ProviderConfigProperty.LIST_TYPE);
        didMethodProperty.setHelpText("Select the DID method to use. Determines which fields below are applicable.");
        didMethodProperty.setOptions(Arrays.asList("web", "sov"));
        didMethodProperty.setDefaultValue("web");
        properties.add(didMethodProperty);

        // SSI Endpoint
        ProviderConfigProperty ssiEndpointProperty = new ProviderConfigProperty();
        ssiEndpointProperty.setName("ssi_endpoint");
        ssiEndpointProperty.setLabel("SSI Endpoint");
        ssiEndpointProperty.setType(ProviderConfigProperty.STRING_TYPE);
        ssiEndpointProperty.setHelpText("The API URL of the SSI verifier or agent.");
        properties.add(ssiEndpointProperty);

        // Bearer Token (Optional)
        ProviderConfigProperty bearerTokenProperty = new ProviderConfigProperty();
        bearerTokenProperty.setName("ssi_bearer_token");
        bearerTokenProperty.setLabel("Bearer Token");
        bearerTokenProperty.setType(ProviderConfigProperty.PASSWORD);
        bearerTokenProperty.setHelpText("Optional: Token used for authorization with the SSI endpoint.");
        properties.add(bearerTokenProperty);

        // Proof Request JSON (for did:sov only)
        ProviderConfigProperty jsonConfigProperty = new ProviderConfigProperty();
        jsonConfigProperty.setName("proof_request_json");
        jsonConfigProperty.setLabel("Proof Request JSON (for DID Sov)");
        jsonConfigProperty.setType(ProviderConfigProperty.STRING_TYPE);
        jsonConfigProperty.setHelpText("Only applicable when DID method is 'sov'. Example: {\"schema_id\":\"...\",\"attributes\":[\"name\"]}");
        jsonConfigProperty.setDefaultValue("{\"schema_id\":\"\",\"attributes\":[]}");
        properties.add(jsonConfigProperty);

        // Credential Type (for did:web only)
        ProviderConfigProperty credentialTypeProperty = new ProviderConfigProperty();
        credentialTypeProperty.setName("credential_type");
        credentialTypeProperty.setLabel("Credential Format (for DID Web)");
        credentialTypeProperty.setType(ProviderConfigProperty.LIST_TYPE);
        credentialTypeProperty.setHelpText("Only applicable when DID method is 'web'. Choose the credential format.");
        credentialTypeProperty.setOptions(Arrays.asList("jwt_w3c_vc", "sd_jwt_w3c_vc"));
        credentialTypeProperty.setDefaultValue("jwt_w3c_vc");
        properties.add(credentialTypeProperty);


        // Issuer DID
        ProviderConfigProperty issuerDidProperty = new ProviderConfigProperty();
        issuerDidProperty.setName("issuer_did");
        issuerDidProperty.setLabel("Issuer DID");
        issuerDidProperty.setType(ProviderConfigProperty.STRING_TYPE);
        issuerDidProperty.setHelpText("Decentralized Identifier (DID) of the issuer. Example: did:key:xyz123");
        issuerDidProperty.setDefaultValue("did:key:example");
        properties.add(issuerDidProperty);

        ProviderConfigProperty requestedCredentialProperty = new ProviderConfigProperty();
        requestedCredentialProperty.setName("requested_credential");
        requestedCredentialProperty.setLabel("Requested Credential Configuration");
        requestedCredentialProperty.setType(ProviderConfigProperty.STRING_TYPE);
        requestedCredentialProperty.setHelpText(
                "Enter credential configuration in JSON format. " +
                        "Example: { \"credential_type\": \"EducationalID\", \"attributes\": [\"name\", \"birthDate\", \"school\"] }"
        );
        requestedCredentialProperty.setDefaultValue("{ \"credential_type\": \"EducationalID\", \"attributes\": [\"name\", \"school\"] }");
        properties.add(requestedCredentialProperty);

        return properties;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new SSIAuth(); // Create new instance of authenticator
    }

    @Override
    public void init(Config.Scope config) {
        // Initialize global configuration if needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post-initialization logic if needed
    }

    @Override
    public void close() {
        // Cleanup logic if needed
    }
}
