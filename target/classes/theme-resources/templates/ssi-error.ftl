<#import "template.ftl" as layout>

<@layout.registrationLayout displayInfo=true; section>

<#if section == "header">

<#elseif section == "form">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

  <style>
    html, body {
      background: linear-gradient(180deg, #1e3a5f 0%, #0f2744 100%) !important;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
      min-height: 100vh !important;
    }

    .card-pf {
      background: #ffffff !important;
      border-radius: 10px !important;
      box-shadow: 0 8px 28px rgba(15, 39, 68, 0.28) !important;
      max-width: 560px !important;
      margin: 2rem auto !important;
      padding: 0 !important;
      overflow: hidden !important;
      border-top: 4px solid #c41230 !important;
    }

    .ssi-error-shell {
      padding: 0;
    }

    .ssi-error-header {
      background: linear-gradient(135deg, #1e3a5f 0%, #2c5282 100%);
      color: #fff;
      padding: 1.5rem 2rem;
      text-align: center;
      border-bottom: 3px solid #c41230;
    }

    .ssi-error-header h1 {
      margin: 0;
      font-size: 1.25rem;
      font-weight: 700;
    }

    .ssi-error-body {
      padding: 2rem;
    }

    .ssi-error-banner {
      display: flex;
      gap: 0.875rem;
      align-items: flex-start;
      background: #fff5f5;
      border: 1px solid #feb2b2;
      border-radius: 10px;
      padding: 1rem 1rem 1rem 0.875rem;
      color: #742a2a;
      margin-bottom: 1.25rem;
    }

    .ssi-error-icon {
      width: 40px;
      height: 40px;
      min-width: 40px;
      border-radius: 999px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #c41230;
      color: #fff;
    }

    .ssi-error-title {
      margin: 0 0 0.625rem 0;
      color: #1a202c;
      font-size: 1.2rem;
      font-weight: 700;
    }

    .ssi-error-copy {
      margin: 0 0 1rem 0;
      color: #4a5568;
      line-height: 1.65;
      font-size: 0.95rem;
    }

    .ssi-error-note {
      background: #f7fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 1rem;
      color: #2d3748;
      font-size: 0.92rem;
      line-height: 1.55;
      margin-bottom: 1.5rem;
    }

    .ssi-error-actions {
      display: flex;
      gap: 0.875rem;
      flex-wrap: wrap;
    }

    .ssi-btn {
      appearance: none;
      border: none;
      border-radius: 8px;
      padding: 0.95rem 1.25rem;
      font-size: 0.95rem;
      font-weight: 700;
      cursor: pointer;
      min-height: 48px;
      transition: transform 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
    }

    .ssi-btn:focus-visible {
      outline: 3px solid rgba(49, 130, 206, 0.45);
      outline-offset: 2px;
    }

    .ssi-btn-primary {
      flex: 1 1 240px;
      background: linear-gradient(135deg, #c41230 0%, #9a0f26 100%);
      color: #fff;
      box-shadow: 0 8px 20px rgba(196, 18, 48, 0.22);
    }

    .ssi-btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 10px 24px rgba(196, 18, 48, 0.3);
    }

    .ssi-btn-secondary {
      flex: 1 1 180px;
      background: #edf2f7;
      color: #2d3748;
      border: 1px solid #d9e2ec;
    }

    .ssi-btn-secondary:hover {
      background: #e2e8f0;
    }

    @media (max-width: 640px) {
      .ssi-error-header,
      .ssi-error-body {
        padding: 1.25rem;
      }

      .ssi-error-actions {
        flex-direction: column;
      }

      .ssi-btn {
        width: 100%;
      }
    }
  </style>

  <div class="ssi-error-shell">
    <div class="ssi-error-header">
      <h1>SSI verification problem</h1>
    </div>

    <div class="ssi-error-body">
      <div class="ssi-error-banner" role="alert" aria-live="polite">
        <div class="ssi-error-icon" aria-hidden="true">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
        </div>
        <div>
          <h2 class="ssi-error-title">${ssiErrorTitle!"SSI verification unavailable"}</h2>
          <p class="ssi-error-copy">${ssiErrorMessage!"Digital identity verification failed. You can continue login without SSI verification."}</p>
        </div>
      </div>

      <div class="ssi-error-note">
        You can continue the login process without SSI verification. The system will mark this session as skipped for SSI validation.
      </div>

      <div class="ssi-error-actions">
        <form action="${url.loginAction}" method="post" style="flex: 1 1 240px; margin: 0;">
          <input type="hidden" name="execution" value="${execution}" />
          <input type="hidden" name="skip_ssi" value="true" />
          <button type="submit" class="ssi-btn ssi-btn-primary">Continue without verification</button>
        </form>

        <form action="${url.loginAction}" method="post" style="flex: 1 1 180px; margin: 0;">
          <input type="hidden" name="execution" value="${execution}" />
          <input type="hidden" name="retry_ssi" value="true" />
          <button type="submit" class="ssi-btn ssi-btn-secondary">Try again</button>
        </form>
      </div>
    </div>
  </div>

<#elseif section == "info">
</#if>

</@layout.registrationLayout>
