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

    <@comp.hiddenAuthForm url.loginAction />
  </div>

  <#if sessionId??>
    <script src="${url.resourcesPath}/ssi-auth.js"></script>
    <script>
      SSIAuth.startPolling({
        realm: '${realm.name}',
        sessionId: '${sessionId}',
        tabId: new URLSearchParams(window.location.search).get('execution'),
        onStatusChange: function(data, attempts) {
          SSIAuth.updateCounter('polling-counter', attempts, 60);
        },
        onComplete: function(data) {
          SSIAuth.hideRetryButton('retry-button');
          SSIAuth.submitForm('kc-qr-code-login-form');
        },
        onError: function(error) {
          if (error.message === 'max_attempts_reached') {
            SSIAuth.showError('error-message', '${msg("ssiMaxAttemptsReached")?js_string}');
            SSIAuth.showRetryButton('retry-button');
          } else if (error.message && error.message.includes('Failed to fetch')) {
            SSIAuth.showError('error-message', '${msg("ssiConnectionError")?js_string}');
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
