<#import "template.ftl" as layout>
<#import "ssi-components.ftl" as comp>

<@layout.registrationLayout displayInfo=true; section>

<#if section == "header">
  <!-- Hide default header, we'll use our own -->

<#elseif section == "form">
  <link href="${url.resourcesPath}/ssi-auth.css" rel="stylesheet" />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  
  <style>
    /* Override for this template */
    html, body {
      background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%) !important;
      background-attachment: fixed !important;
    }
    
    .card-pf {
      background: rgba(255, 255, 255, 0.95) !important;
      backdrop-filter: blur(20px) !important;
      border: 1px solid rgba(255, 255, 255, 0.5) !important;
      box-shadow: 0 8px 32px rgba(31, 38, 135, 0.15) !important;
      border-radius: 24px !important;
    }
  </style>

  <div class="ssi-auth-container">
    <@comp.verificationHeader msg("ssiAuthWaitingTitle") />
    <@comp.verificationInstructions msg("ssiAuthWaitingInstruction") />

    <@comp.progressIndicator totalSteps=2 />

    <@comp.statusIndicator status="active" />

    <@comp.loadingSpinner msg("ssiAuthVerificationStatus") />

    <@comp.pollingCounter maxAttempts=60 />
    <@comp.errorMessage id="error-message" />
    <@comp.retryButton />

    <@comp.hiddenLoginForm url.loginAction execution />

    <form id="ssi-error-form" action="${url.loginAction}" method="post" style="display:none;">
      <input type="hidden" name="execution" value="${execution}" />
      <input type="hidden" name="show_ssi_error" value="true" />
      <input type="hidden" name="ssi_error_title" id="ssi-error-title-input" value="" />
      <input type="hidden" name="ssi_error_message" id="ssi-error-message-input" value="" />
    </form>
  </div>

  <#if sessionId??>
    <script src="${url.resourcesPath}/ssi-auth.js"></script>
    <script>
      function redirectToSsiErrorPage(title, message) {
        var form = document.getElementById('ssi-error-form');
        var titleInput = document.getElementById('ssi-error-title-input');
        var messageInput = document.getElementById('ssi-error-message-input');

        if (!form || !titleInput || !messageInput) {
          return;
        }

        titleInput.value = title || 'SSI verification unavailable';
        messageInput.value = message || 'Digital identity verification failed. You can continue login without SSI verification.';
        form.submit();
      }

      SSIAuth.startPolling({
        realm: '${realm.name}',
        sessionId: '${sessionId}',
        tabId: '${tabId!""}' || new URLSearchParams(window.location.search).get('tab_id') || new URLSearchParams(window.location.search).get('tabId'),
        onStatusChange: function(data, attempts) {
          SSIAuth.updateCounter('polling-counter', attempts, 60);

          if (data.reasonCode === 'session_expired' || data.reasonCode === 'invalid_tab') {
            redirectToSsiErrorPage(
              'SSI session expired',
              'The SSI verification session expired before completion. You can continue login without SSI verification.'
            );
            return;
          }

          if (data.reasonCode === 'unauthorized' || data.reasonCode === 'internal_error') {
            redirectToSsiErrorPage(
              'SSI verification unavailable',
              'The SSI service could not complete verification. You can continue login without SSI verification.'
            );
            return;
          }

          if (data.status === 'invalid' || data.status === 'failed') {
            redirectToSsiErrorPage(
              'SSI verification failed',
              'Credential verification failed. You can continue login without SSI verification.'
            );
          }
        },
        onComplete: function(data) {
          SSIAuth.hideRetryButton('retry-button');
          SSIAuth.submitForm('kc-qr-code-login-form');
        },
        onError: function(error) {
          if (error.message === 'max_attempts_reached') {
            redirectToSsiErrorPage(
              'SSI verification timed out',
              'Digital identity verification took too long. You can continue login without SSI verification.'
            );
          } else if (error.message && error.message.includes('Failed to fetch')) {
            redirectToSsiErrorPage(
              'SSI connection error',
              'The SSI service could not be reached. You can continue login without SSI verification.'
            );
          } else {
            redirectToSsiErrorPage(
              'SSI verification unavailable',
              'The SSI verification flow hit an unexpected error. You can continue login without SSI verification.'
            );
          }
        },
        debug: false
      });
    </script>
  <#else>
    <script>
      console.warn('[SSI Auth] sessionId not available in template.');
    </script>
  </#if>

<#elseif section == "info">
</#if>

</@layout.registrationLayout>
