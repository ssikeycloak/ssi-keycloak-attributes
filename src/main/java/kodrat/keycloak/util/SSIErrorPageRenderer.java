package kodrat.keycloak.util;

import org.keycloak.authentication.AuthenticationFlowContext;

public final class SSIErrorPageRenderer {

    private static final String DEFAULT_TITLE = "SSI verification unavailable";
    private static final String DEFAULT_MESSAGE = "Digital identity verification failed. You can continue login without SSI verification.";

    private SSIErrorPageRenderer() {
    }

    public static void render(AuthenticationFlowContext context, String title, String message) {
        String resolvedTitle = title == null || title.isBlank() ? DEFAULT_TITLE : title;
        String resolvedMessage = message == null || message.isBlank() ? DEFAULT_MESSAGE : message;

        context.challenge(context.form()
                .setAttribute("ssiErrorTitle", resolvedTitle)
                .setAttribute("ssiErrorMessage", resolvedMessage)
                .createForm("ssi-error.ftl"));
    }
}
