<#import "template.ftl" as layout>

<@layout.registrationLayout displayInfo=true; section>

<#if section == "header">

<#elseif section == "form">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  
  <style>
    /* GOVERNMENT STYLE - Professional & Formal */
    html, body { 
      background: linear-gradient(180deg, #1e3a5f 0%, #0f2744 100%) !important; 
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
      min-height: 100vh !important;
    }
    
    .card-pf { 
      background: #ffffff !important; 
      border-radius: 8px !important; 
      box-shadow: 0 4px 20px rgba(0,0,0,0.3) !important;
      max-width: 520px !important;
      margin: 2rem auto !important;
      padding: 0 !important;
      overflow: hidden !important;
      border-top: 4px solid #c41230 !important;
    }
    
    .gov-header {
      background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
      color: white;
      padding: 1.5rem 2rem;
      text-align: center;
      border-bottom: 3px solid #c41230;
    }
    
    .gov-header h2 {
      margin: 0;
      font-size: 1.25rem;
      font-weight: 600;
      letter-spacing: 0.5px;
    }
    
    .gov-header .subtitle {
      margin: 0.5rem 0 0 0;
      font-size: 0.875rem;
      opacity: 0.9;
      font-weight: 400;
    }
    
    .gov-content {
      padding: 2rem;
    }
    
    .gov-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: #f7fafc;
      border: 1px solid #e2e8f0;
      padding: 0.5rem 1rem;
      border-radius: 4px;
      font-size: 0.75rem;
      color: #4a5568;
      margin-bottom: 1.5rem;
    }
    
    .gov-badge svg {
      width: 16px;
      height: 16px;
      color: #c41230;
    }
    
    .gov-title {
      color: #1a202c;
      font-size: 1.25rem;
      font-weight: 700;
      margin-bottom: 1rem;
      text-align: center;
    }
    
    .gov-description {
      color: #4a5568;
      font-size: 0.9375rem;
      line-height: 1.6;
      margin-bottom: 1.5rem;
      text-align: center;
    }
    
    .data-requirements {
      background: #f7fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1.5rem;
    }
    
    .data-requirements h3 {
      color: #1a202c;
      font-size: 0.875rem;
      font-weight: 600;
      margin: 0 0 0.75rem 0;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .data-list {
      list-style: none;
      padding: 0;
      margin: 0;
    }
    
    .data-list li {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      padding: 0.5rem 0;
      color: #2d3748;
      font-size: 0.9375rem;
      border-bottom: 1px solid #edf2f7;
    }
    
    .data-list li:last-child {
      border-bottom: none;
    }
    
    .data-list li::before {
      content: "✓";
      display: flex;
      align-items: center;
      justify-content: center;
      width: 20px;
      height: 20px;
      background: #c41230;
      color: white;
      border-radius: 50%;
      font-size: 0.75rem;
      font-weight: 700;
    }
    
    .privacy-notice {
      background: #ebf8ff;
      border-left: 4px solid #3182ce;
      padding: 1rem;
      margin-bottom: 1.5rem;
      font-size: 0.875rem;
      color: #2c5282;
      border-radius: 0 4px 4px 0;
    }
    
    .privacy-notice strong {
      color: #1a365d;
      display: block;
      margin-bottom: 0.25rem;
    }
    
    .button-group {
      display: flex;
      gap: 1rem;
      margin-top: 1.5rem;
    }
    
    .btn {
      flex: 1;
      padding: 0.875rem 1.5rem;
      border: none;
      border-radius: 6px;
      font-size: 0.9375rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      text-align: center;
    }
    
    .btn-primary {
      background: linear-gradient(135deg, #c41230 0%, #9a0f26 100%);
      color: white;
      box-shadow: 0 2px 8px rgba(196, 18, 48, 0.3);
    }
    
    .btn-primary:hover {
      background: linear-gradient(135deg, #a81028 0%, #7a0d1e 100%);
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(196, 18, 48, 0.4);
    }
    
    .btn-secondary {
      background: #edf2f7;
      color: #4a5568;
      border: 1px solid #e2e8f0;
    }
    
    .btn-secondary:hover {
      background: #e2e8f0;
      color: #2d3748;
    }
    
    /* QR Code View Styles */
    .qr-view {
      text-align: center;
    }
    
    .qr-view h1 {
      color: #1a202c;
      font-size: 1.25rem;
      margin-bottom: 0.5rem;
    }
    
    .qr-view p {
      color: #718096;
      font-size: 0.9375rem;
      margin-bottom: 1.5rem;
    }
    
    .progress-bar {
      display: flex;
      justify-content: center;
      gap: 0.5rem;
      margin: 1.5rem 0;
    }
    
    .progress-step {
      flex: 1;
      max-width: 100px;
      text-align: center;
    }
    
    .progress-step-dot {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: #e2e8f0;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 0.5rem;
      font-weight: 700;
      font-size: 0.875rem;
      color: #718096;
      border: 2px solid #e2e8f0;
    }
    
    .progress-step.active .progress-step-dot {
      background: #c41230;
      color: white;
      border-color: #c41230;
    }
    
    .progress-step.completed .progress-step-dot {
      background: #38a169;
      color: white;
      border-color: #38a169;
    }
    
    .progress-step-label {
      font-size: 0.75rem;
      color: #718096;
      font-weight: 500;
    }
    
    .progress-step.active .progress-step-label {
      color: #c41230;
      font-weight: 600;
    }
    
    .qr-container {
      background: #f7fafc;
      padding: 1.5rem;
      border-radius: 8px;
      display: inline-block;
      margin: 1rem 0;
      border: 1px solid #e2e8f0;
    }
    
    .qr-container img {
      max-width: 200px;
      border-radius: 4px;
    }
    
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      background: #fef5e7;
      border: 1px solid #fbd38d;
      border-radius: 50px;
      font-size: 0.875rem;
      color: #975a16;
      margin-top: 1rem;
    }
    
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #ed8936;
      animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.5; }
    }
    
    .hidden { display: none !important; }
    
    .tech-info {
      background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 1rem 1.25rem;
      margin-bottom: 1.5rem;
      text-align: left;
    }
    
    .tech-row {
      display: flex;
      justify-content: space-between;
      padding: 0.375rem 0;
      border-bottom: 1px solid #e2e8f0;
      font-size: 0.875rem;
    }
    
    .tech-row:last-child {
      border-bottom: none;
    }
    
    .tech-label {
      color: #718096;
      font-weight: 500;
    }
    
    .tech-value {
      color: #2d3748;
      font-weight: 600;
      font-family: monospace;
      background: #edf2f7;
      padding: 0.125rem 0.5rem;
      border-radius: 4px;
    }

    .process-flow {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 1rem;
      margin: 1.5rem 0;
      padding: 1rem;
      background: #f7fafc;
      border-radius: 8px;
    }
    
    .process-step {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      opacity: 0.5;
    }
    
    .process-step.active {
      opacity: 1;
    }
    
    .process-step.completed {
      opacity: 1;
    }
    
    .process-icon {
      width: 36px;
      height: 36px;
      border-radius: 50%;
      background: #e2e8f0;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      font-size: 0.875rem;
      color: #718096;
      border: 2px solid #e2e8f0;
    }
    
    .process-step.active .process-icon {
      background: #c41230;
      color: white;
      border-color: #c41230;
    }
    
    .process-step.completed .process-icon {
      background: #38a169;
      color: white;
      border-color: #38a169;
    }
    
    .process-text {
      display: flex;
      flex-direction: column;
      text-align: left;
    }
    
    .process-text strong {
      font-size: 0.875rem;
      color: #1a202c;
    }
    
    .process-text span {
      font-size: 0.75rem;
      color: #718096;
    }
    
    .process-arrow {
      font-size: 1.25rem;
      color: #a0aec0;
      font-weight: 700;
    }
    
    .qr-label {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      margin-top: 0.75rem;
      font-size: 0.75rem;
      color: #718096;
      font-weight: 500;
    }
    
    .help-text {
      background: #f0fff4;
      border: 1px solid #9ae6b4;
      border-radius: 8px;
      padding: 1rem;
      margin-top: 1.5rem;
      text-align: left;
    }
    
    .help-text p {
      margin: 0 0 0.5rem 0;
      color: #22543d;
      font-size: 0.875rem;
    }
    
    .help-text ol {
      margin: 0;
      padding-left: 1.25rem;
      color: #2f855a;
      font-size: 0.8125rem;
      line-height: 1.6;
    }
    
    .help-text li {
      margin-bottom: 0.25rem;
    }

    .schema-info {
      margin-top: 1rem;
      padding-top: 0.75rem;
      border-top: 1px dashed #e2e8f0;
      font-size: 0.75rem;
      color: #718096;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .schema-label {
      font-weight: 600;
      color: #4a5568;
    }

    .schema-value {
      font-family: monospace;
      background: #edf2f7;
      padding: 0.125rem 0.5rem;
      border-radius: 4px;
      max-width: 200px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .back-link {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      color: #4a5568;
      font-size: 0.875rem;
      text-decoration: none;
      margin-bottom: 1rem;
      cursor: pointer;
    }
    
    .back-link:hover {
      color: #2d3748;
    }
  </style>

  <div id="consent-view" class="gov-content">
    <div class="gov-badge">
      <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
      </svg>
      Digital Identity Verification
    </div>
    
    <h1 class="gov-title">Identity Data Request</h1>
    
    <p class="gov-description">
      To continue the authentication process, the system needs access to the following identity data from your digital wallet:
    </p>
    
    <div class="data-requirements">
      <h3>Required Data:</h3>
      <ul class="data-list">
        <#if requestedAttributes?? && requestedAttributes?size gt 0>
          <#list requestedAttributes as attr>
            <li>
              <#if attr == "name">Full Name
              <#elseif attr == "NIK">National ID Number (NIK)
              <#elseif attr == "email">Email Address
              <#elseif attr == "phone">Phone Number
              <#elseif attr == "school">Institution/University
              <#elseif attr == "degree">Education Level
              <#elseif attr == "student_id">Student ID Number
              <#elseif attr == "birth_date">Date of Birth
              <#else>${attr?cap_first}</#if>
            </li>
          </#list>
        <#else>
          <li>Full Name</li>
          <li>National ID Number (NIK)</li>
          <li>Email Address</li>
          <li>Phone Number</li>
        </#if>
      </ul>
      <#if schemaName?? || schemaId??>
      <div class="schema-info">
        <span class="schema-label">Schema:</span>
        <span class="schema-value" title="${schemaId!''}">${schemaName!schemaId!''}</span>
      </div>
      </#if>
      <#if issuerName?? || issuerDid??>
      <div class="schema-info">
        <span class="schema-label">Issuer:</span>
        <span class="schema-value" title="${issuerDid!''}">${issuerName!issuerDid!''}</span>
      </div>
      </#if>
    </div>
    
    <div class="privacy-notice">
      <strong>Data Security</strong>
      Your data will be verified using secure and encrypted Self-Sovereign Identity (SSI) technology. The data will not be stored permanently by the system.
    </div>
    
    <div class="button-group">
      <button type="button" class="btn btn-secondary" onclick="skipVerification()">
        Skip
      </button>
      <button type="button" class="btn btn-primary" onclick="showQRCode()">
        Continue Verification
      </button>
    </div>
  </div>

  <#assign isDidWeb = (didMethod?? && didMethod?lower_case == "web")>

  <div id="qr-view" class="gov-content hidden">
    <a class="back-link" onclick="showConsent()">
      <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"></path>
      </svg>
      Back
    </a>
    
    <div class="qr-view">
      <h1>Connect Wallet</h1>
      <p>Scan the QR code to establish a connection with your digital wallet</p>
      
      <div class="tech-info">
        <div class="tech-row">
          <span class="tech-label">Metode:</span>
          <span class="tech-value">${methodDisplay!'Sovrin (did:sov)'}</span>
        </div>
        <div class="tech-row">
          <span class="tech-label">Protokol:</span>
          <span class="tech-value">${protocolDisplay!'DIDComm/ACA-Py'}</span>
        </div>
        <div class="tech-row" id="connection-row" style="display: none;">
          <span class="tech-label">Connection ID:</span>
          <span class="tech-value" id="connection-id">-</span>
        </div>
      </div>
      
      <div class="process-flow">
        <div class="process-step active">
          <div class="process-icon">1</div>
          <div class="process-text">
            <strong>Verification</strong>
            <#if isDidWeb>
              <span>Scan QR and approve in wallet</span>
            <#else>
              <span>Scan QR, connect, then approve proof</span>
            </#if>
          </div>
        </div>
      </div>

      <div class="qr-container" id="qr-container">
        <div id="qr-loading" class="qr-loading">
          <div class="spinner"></div>
          <p>Generating QR code...</p>
        </div>
        <img src="${qrCode!''}" alt="Kode QR" id="qr-image" onerror="handleQrLoadError()" onload="showQRImage()" style="display: none;" />
        <div class="qr-label" id="qr-label" style="display: none;">
          <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
          </svg>
          <#if isDidWeb>
            OpenID4VC authorization URL
          <#else>
            Invitation URL for DIDComm connection
          </#if>
        </div>
      </div>

      <div class="status-pill" id="status-pill">
        <div class="status-dot"></div>
        <span id="status-text"><#if isDidWeb>Waiting for wallet approval...<#else>Waiting for connection...</#if></span>
      </div>
      
    </div>
  </div>

   <form id="skip-form" action="${url.loginAction}" method="post" class="hidden">
     <input type="hidden" name="execution" value="${execution}" />
     <input type="hidden" name="skip_ssi" value="true" />
   </form>

   <form id="auth-form" action="${url.loginAction}" method="post" class="hidden">
     <input type="hidden" name="execution" value="${execution}" />
   </form>

   <form id="retry-form" action="${url.loginAction}" method="post" class="hidden">
     <input type="hidden" name="execution" value="${execution}" />
     <input type="hidden" name="retry_ssi" value="true" />
   </form>

   <form id="error-form" action="${url.loginAction}" method="post" class="hidden">
     <input type="hidden" name="execution" value="${execution}" />
     <input type="hidden" name="show_ssi_error" value="true" />
     <input type="hidden" name="ssi_error_title" id="ssi-error-title-input" value="" />
     <input type="hidden" name="ssi_error_message" id="ssi-error-message-input" value="" />
   </form>

   <div id="retry-controls" class="button-group hidden" style="margin-top: 1.5rem; justify-content: center;">
     <button type="button" id="retry-button" class="btn btn-primary" onclick="handleRetry()" style="max-width: 260px;">
       Retry Verification
     </button>
   </div>

   <style>
     .btn-loading {
       opacity: 0.7;
       cursor: not-allowed;
       position: relative;
     }
     .btn-loading::after {
       content: '';
       position: absolute;
       width: 16px;
       height: 16px;
       border: 2px solid transparent;
       border-top-color: white;
       border-radius: 50%;
       animation: spin 1s linear infinite;
       margin-left: 8px;
     }
     @keyframes spin {
       to { transform: rotate(360deg); }
     }
      .error-pill {
        background: #fff5f5 !important;
        border-color: #feb2b2 !important;
        color: #9b2c2c !important;
      }
      .success-pill {
        background: #f0fff4 !important;
        border-color: #9ae6b4 !important;
        color: #22543d !important;
      }
      .qr-loading {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 2rem;
        min-height: 200px;
      }
      .qr-loading p {
        margin-top: 1rem;
        color: #718096;
        font-size: 0.875rem;
      }
      .spinner {
        width: 40px;
        height: 40px;
        border: 3px solid #e2e8f0;
        border-top-color: #c41230;
        border-radius: 50%;
        animation: spin 1s linear infinite;
      }
      @keyframes spin {
        to { transform: rotate(360deg); }
      }
    </style>

   <script>
     var pollIntervalId = null;
     var pollingStarted = false;
     var pollRequestInFlight = false;
     var authSubmitStarted = false;
     var retryInProgress = false;

     function stopPolling() {
       if (pollIntervalId) {
         clearInterval(pollIntervalId);
         pollIntervalId = null;
       }
       pollingStarted = false;
     }

     function showRetryButton() {
       var retryControls = document.getElementById('retry-controls');
       if (retryControls) {
         retryControls.classList.remove('hidden');
       }
     }

     function hideRetryButton() {
       var retryControls = document.getElementById('retry-controls');
       if (retryControls) {
         retryControls.classList.add('hidden');
       }
     }

     function setButtonLoading(loading) {
       var retryBtn = document.getElementById('retry-button');
       if (retryBtn) {
         if (loading) {
           retryBtn.classList.add('btn-loading');
           retryBtn.disabled = true;
           retryBtn.textContent = 'Retrying...';
         } else {
           retryBtn.classList.remove('btn-loading');
           retryBtn.disabled = false;
           retryBtn.textContent = 'Retry Verification';
         }
       }
     }

      function handleRetry() {
        if (retryInProgress) {
          return;
        }

        var effectiveTabId = getEffectiveTabId();
        if (!effectiveTabId) {
          redirectToErrorPage(
            'SSI session unavailable',
            'The SSI session context is missing. You can continue login without SSI verification.'
          );
          return;
        }

        retryInProgress = true;
        setButtonLoading(true);

       // First, try to reset via API endpoint
        var retryUrl = '/realms/${realm.name}/custom-resource/retry';
        var formData = new FormData();
        formData.append('sessionId', '${sessionId!""}');
        formData.append('tabId', effectiveTabId);

       fetch(retryUrl, {
         method: 'POST',
         body: formData
       })
       .then(r => r.json())
       .then(data => {
           if (data.status === 'reset-ok' || data.reasonCode === 'reset_ok') {
             // Reset successful, restart polling
             var statusPill = document.getElementById('status-pill');
             statusPill.classList.remove('error-pill');
             statusPill.classList.add('success-pill');
             document.getElementById('status-text').textContent = 'Reset successful. Generating new QR code...';

             // Show loading state and clear stale QR
             showQRLoading();
             var qrImage = document.getElementById('qr-image');
             if (qrImage) {
               qrImage.removeAttribute('src');
             }
            
            setTimeout(function() {
              hideRetryButton();
              setButtonLoading(false);
              retryInProgress = false;
             
             // Reset polling state
             authSubmitStarted = false;
             pollingStarted = false;
             
             // Restart polling
             startPolling();
           }, 1000);
         } else if (data.reasonCode === 'session_expired' || data.reasonCode === 'invalid_tab') {
           // Non-recoverable - use form-based retry
           document.getElementById('status-text').textContent = 'Session expired. Redirecting...';
           setTimeout(function() {
             document.getElementById('retry-form').submit();
           }, 1000);
         } else {
           // Other error - fallback to form-based retry
           document.getElementById('retry-form').submit();
         }
       })
       .catch(function(err) {
         console.error('Retry API error:', err);
         // Fallback to form-based retry
         document.getElementById('retry-form').submit();
       });
     }

      function showErrorWithRetry(message) {
        var statusPill = document.getElementById('status-pill');
        statusPill.classList.remove('success-pill');
        statusPill.classList.add('error-pill');
        document.getElementById('status-text').textContent = message;
        showRetryButton();
      }

      function getEffectiveTabId() {
        var fixedTabId = '${tabId!""}'.trim();

        if (!fixedTabId) {
          var params = new URLSearchParams(window.location.search);
          fixedTabId = (params.get('tab_id') || params.get('tabId') || '').trim();
        }

        return fixedTabId;
      }

       function showQRLoading() {
         var loadingEl = document.getElementById('qr-loading');
         var qrImage = document.getElementById('qr-image');
         var qrLabel = document.getElementById('qr-label');
         if (loadingEl) loadingEl.style.display = 'flex';
         if (qrImage) qrImage.style.display = 'none';
         if (qrLabel) qrLabel.style.display = 'none';
       }

       function showQRImage() {
         var loadingEl = document.getElementById('qr-loading');
         var qrImage = document.getElementById('qr-image');
         var qrLabel = document.getElementById('qr-label');
         if (loadingEl) loadingEl.style.display = 'none';
         if (qrImage) qrImage.style.display = 'block';
         if (qrLabel) qrLabel.style.display = 'flex';
       }

       function updateQRCodeIfPresent(qrCodeUrl) {
         var qrImage = document.getElementById('qr-image');
         if (!qrImage) {
           return;
         }
         if (!qrCodeUrl || qrCodeUrl === '') {
           // Don't show error yet, just keep loading state
           showQRLoading();
           return;
         }
         setQrImageSource(qrImage, qrCodeUrl);
       }

       function setQrImageSource(qrImage, qrCodeUrl) {
         if (!qrImage || !qrCodeUrl) {
           return;
         }
         try {
           var parsed = new URL(qrCodeUrl, window.location.origin);
           parsed.searchParams.set('_ts', Date.now().toString());
           qrImage.src = parsed.toString();
         } catch (e) {
           qrImage.src = qrCodeUrl;
         }
       }

       function handleQrLoadError() {
           // Only show error if we're not polling or if polling has failed
           if (pollRequestInFlight) {
             // Still polling, don't show error yet
             return;
           }
          var statusPill = document.getElementById('status-pill');
          if (statusPill) {
            statusPill.classList.remove('success-pill');
            statusPill.classList.add('error-pill');
          }
          var statusText = document.getElementById('status-text');
          if (statusText) {
            statusText.textContent = 'QR image failed to load. Please wait or click Retry Verification.';
          }
          showRetryButton();
         }

      function showQRCode() {
       document.getElementById('consent-view').classList.add('hidden');
       document.getElementById('qr-view').classList.remove('hidden');

       // Show loading state initially
       showQRLoading();

       if (!pollingStarted) {
         startPolling();
       }

       // Both DID methods are progressed by /status polling to avoid duplicate backend execution.
       return;
     }
    
    function showConsent() {
      document.getElementById('qr-view').classList.add('hidden');
      document.getElementById('consent-view').classList.remove('hidden');
    }
    
    function skipVerification() {
      if (confirm('Are you sure you want to skip digital identity verification?')) {
        document.getElementById('skip-form').submit();
      }
    }

    function redirectToErrorPage(title, message) {
      stopPolling();

      var titleInput = document.getElementById('ssi-error-title-input');
      var messageInput = document.getElementById('ssi-error-message-input');
      var errorForm = document.getElementById('error-form');

      if (!errorForm || !titleInput || !messageInput) {
        showErrorWithRetry(message || 'SSI verification failed. Please retry.');
        return;
      }

      titleInput.value = title || 'SSI verification unavailable';
      messageInput.value = message || 'Digital identity verification failed. You can continue login without SSI verification.';
      errorForm.submit();
    }
    
    function startPolling() {
      <#if sessionId??>
      if (pollingStarted) {
        return;
      }
      pollingStarted = true;

      var attempts = 0;
      var maxAttempts = 60;
      var connectionEstablished = false;
      var fixedTabId = getEffectiveTabId();

      if (!fixedTabId) {
        redirectToErrorPage(
          'SSI session unavailable',
          'The SSI session context is missing. You can continue login without SSI verification.'
        );
        return;
      }
      
      function poll() {
        if (authSubmitStarted || pollRequestInFlight || retryInProgress) {
          return;
        }

        if (attempts >= maxAttempts) {
          redirectToErrorPage(
            'SSI verification timed out',
            'Digital identity verification took too long. You can continue login without SSI verification.'
          );
          return;
        }
        
        attempts++;
        var url = '/realms/${realm.name}/custom-resource/status?sessionId=' + encodeURIComponent('${sessionId}') + '&tabId=' + encodeURIComponent(fixedTabId) + '&_ts=' + Date.now();
        pollRequestInFlight = true;
        
        fetch(url, { cache: 'no-store' })
          .then(r => {
            if (!r.ok) {
              return r.text().then(body => {
                throw new Error('status=' + r.status + ', body=' + body);
              });
            }
            return r.json();
          })
          .then(r => {
            var data = r;
            updateQRCodeIfPresent(data.qrCodeUrl);
            
            // Handle reason codes for error states
            if (data.reasonCode) {
              if (data.reasonCode === 'session_expired' || data.reasonCode === 'invalid_tab') {
                redirectToErrorPage(
                  'SSI session expired',
                  'The SSI verification session expired before completion. You can continue login without SSI verification.'
                );
                return;
              }
              if (data.reasonCode === 'unauthorized') {
                redirectToErrorPage(
                  'SSI authorization failed',
                  'The SSI verification request could not be authorized. You can continue login without SSI verification.'
                );
                return;
              }
              if (data.reasonCode === 'internal_error') {
                redirectToErrorPage(
                  'SSI service unavailable',
                  'The SSI service returned an internal error. You can continue login without SSI verification.'
                );
                return;
              }
            }
            
            if (data.status === 'waiting-connection' || data.status === 'waiting-presentation' || data.status === 'done') {
              <#if isDidWeb>
                if (data.status === 'waiting-connection') {
                  document.getElementById('status-text').textContent = 'Waiting for wallet approval...';
                }
                if (data.status === 'waiting-presentation') {
                  document.getElementById('status-text').textContent = 'Wallet approved. Processing verification...';
                }
              <#else>
                if (!connectionEstablished && data.connectionId) {
                  connectionEstablished = true;
                  document.getElementById('connection-id').textContent = data.connectionId.substring(0, 8) + '...';
                  document.getElementById('connection-row').style.display = 'flex';
                  document.getElementById('status-text').textContent = 'Connected. Waiting proof holder...';

                  var statusPill = document.getElementById('status-pill');
                  statusPill.style.background = '#f0fff4';
                  statusPill.style.borderColor = '#9ae6b4';
                  statusPill.style.color = '#22543d';
                }
              </#if>
            }
            
            if (data.status === 'done') {
              if (authSubmitStarted) {
                return;
              }
              authSubmitStarted = true;
              
              var statusPill = document.getElementById('status-pill');
              statusPill.classList.remove('error-pill');
              statusPill.classList.add('success-pill');
              document.getElementById('status-text').textContent = 'Verification successful!';
              
              stopPolling();
              hideRetryButton();
              <#if isDidWeb>
                document.querySelectorAll('.process-step')[0].classList.remove('active');
                document.querySelectorAll('.process-step')[0].classList.add('completed');
              <#else>
                document.querySelectorAll('.process-step')[0].classList.remove('active');
                document.querySelectorAll('.process-step')[0].classList.add('completed');
              </#if>
              setTimeout(() => {
                document.getElementById('auth-form').submit();
              }, 1000);
            }

            if (data.status === 'invalid') {
              if (authSubmitStarted) {
                return;
              }
              redirectToErrorPage(
                'SSI verification failed',
                'Credential verification failed. You can continue login without SSI verification.'
              );
            }
          })
          .catch(err => {
            console.error('Polling error:', err);
            if (authSubmitStarted || retryInProgress) {
              return;
            }
            redirectToErrorPage(
              'SSI connection error',
              'The SSI service could not be reached. You can continue login without SSI verification.'
            );
          })
          .finally(() => {
            pollRequestInFlight = false;
          });
      }

      if (pollIntervalId) {
        clearInterval(pollIntervalId);
      }
      pollIntervalId = setInterval(poll, 3000);
      poll();
      
      </#if>
    }
  </script>

<#elseif section == "info">
</#if>

</@layout.registrationLayout>
