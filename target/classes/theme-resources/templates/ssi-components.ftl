<#--
    Reusable UI Components for SSI Authentication
    Modern Professional Design with SVG Icons
    Usage: <#import "ssi-components.ftl" as comp>
    Then: <@comp.statusIndicator ... />
-->

<#-- SVG Icon Definitions -->
<#macro svgIcon name size="24">
    <#if name == "wallet">
        <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 12V7H5a2 2 0 0 1 0-4h14v4"></path>
            <path d="M3 5v14a2 2 0 0 0 2 2h16v-5"></path>
            <path d="M18 12a2 2 0 0 0 0 4h4v-4Z"></path>
        </svg>
    <#elseif name == "shield">
        <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <path d="m9 12 2 2 4-4"></path>
        </svg>
    <#elseif name == "smartphone">
        <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect width="14" height="20" x="5" y="2" rx="2" ry="2"></rect>
            <path d="M12 18h.01"></path>
        </svg>
    <#elseif name == "lock">
        <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect width="18" height="11" x="3" y="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
    <#elseif name == "check">
        <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M20 6 9 17l-5-5"></path>
        </svg>
    <#elseif name == "refresh">
        <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"></path>
            <path d="M21 3v5h-5"></path>
            <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"></path>
            <path d="M8 16H3v5"></path>
        </svg>
    <#elseif name == "alert">
        <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" x2="12" y1="8" y2="12"></line>
            <line x1="12" x2="12.01" y1="16" y2="16"></line>
        </svg>
    <#elseif name == "qr">
        <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect width="5" height="5" x="3" y="3" rx="1"></rect>
            <rect width="5" height="5" x="16" y="3" rx="1"></rect>
            <rect width="5" height="5" x="3" y="16" rx="1"></rect>
            <path d="M21 16h-3a2 2 0 0 0-2 2v3"></path>
            <path d="M21 21v.01"></path>
            <path d="M12 7v3a2 2 0 0 1-2 2H7"></path>
            <path d="M3 12h.01"></path>
            <path d="M12 3h.01"></path>
            <path d="M12 16v.01"></path>
            <path d="M16 12h1"></path>
            <path d="M21 12v.01"></path>
            <path d="M12 21v-1"></path>
        </svg>
    <#elseif name == "loading">
        <svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="animate-spin">
            <path d="M21 12a9 9 0 1 1-6.219-8.56"></path>
        </svg>
    </#if>
</#macro>

<#macro statusIndicator status="">
    <div class="status-indicator">
        <#if status == "active">
            <div class="status-dot active"></div>
        <#elseif status == "pending">
            <div class="status-dot pending"></div>
        <#elseif status == "error">
            <div class="status-dot error"></div>
        <#else>
            <div class="status-dot"></div>
        </#if>
        <span class="status-text">
            <#if status == "active">
                ${msg("ssiStatusActive")}
            <#elseif status == "pending">
                ${msg("ssiStatusPending")}
            <#elseif status == "error">
                ${msg("ssiStatusError")}
            <#else>
                ${msg("ssiStatusWaiting")}
            </#if>
        </span>
    </div>
</#macro>

<#macro loadingSpinner message="">
    <div class="loading-spinner">
        <div class="spinner-ring"></div>
        <#if message?has_content>
            <p id="verification-status" class="verification-status">
                ${message}
            </p>
        </#if>
    </div>
</#macro>

<#macro qrCodeContainer qrCode alt="">
    <div id="qr-code-container" class="qr-code-container">
        <#if qrCode??>
            <img src="${qrCode}" alt="${alt}" />
        <#else>
            <p class="qr-error">${msg("ssiQrCodeNotAvailable")}</p>
        </#if>
    </div>
</#macro>

<#macro progressIndicator totalSteps=3>
    <div class="progress-indicator">
        <#list 1..totalSteps as step>
            <div class="progress-step" id="progress-step-${step}">
                <div class="progress-step-circle">${step}</div>
                <span class="progress-step-label">${msg("ssiProgressStep" + step)}</span>
            </div>
        </#list>
    </div>
</#macro>

<#macro pollingCounter maxAttempts=60>
    <div id="polling-counter" class="polling-counter">
        ${msg("ssiPollingWaiting")}
    </div>
</#macro>

<#macro retryButton>
    <button id="retry-button" class="retry-button" onclick="SSIAuth.startPolling()">
        <@svgIcon name="refresh" size="16" />
        ${msg("ssiRetryButton")}
    </button>
</#macro>

<#macro errorMessage id="error-message">
    <div id="${id}" class="error-message"></div>
</#macro>

<#macro warningMessage id="warning-message">
    <div id="${id}" class="warning-message"></div>
</#macro>

<#macro walletButton value label icon="">
    <button type="submit" name="wallet" value="${value}" class="wallet-button">
        <#if icon?has_content>
            <#if icon == "smartphone">
                <@svgIcon name="smartphone" size="20" />
            <#elseif icon == "shield">
                <@svgIcon name="shield" size="20" />
            <#elseif icon == "wallet">
                <@svgIcon name="wallet" size="20" />
            <#elseif icon == "lock">
                <@svgIcon name="lock" size="20" />
            </#if>
        </#if>
        ${label}
    </button>
</#macro>

<#macro walletOption value label icon="">
    <div class="wallet-option">
        <div class="wallet-icon">
            <#if icon == "smartphone">
                <@svgIcon name="smartphone" size="28" />
            <#elseif icon == "shield">
                <@svgIcon name="shield" size="28" />
            <#elseif icon == "wallet">
                <@svgIcon name="wallet" size="28" />
            <#elseif icon == "lock">
                <@svgIcon name="lock" size="28" />
            <#else>
                <@svgIcon name="wallet" size="28" />
            </#if>
        </div>
        <button type="submit" name="wallet" value="${value}">${label}</button>
    </div>
</#macro>

<#macro walletGrid>
    <div class="wallet-grid">
        <#nested>
    </div>
</#macro>

<#macro hiddenLoginForm action execution>
    <form id="kc-qr-code-login-form" action="${action}" method="post" class="hidden-form">
        <input type="hidden" name="execution" value="${execution}" />
        <input type="submit" id="auto-submit-button" />
    </form>
</#macro>

<#macro hiddenAuthForm action>
    <form id="kc-qr-code-login-form" action="${action}" method="post" class="hidden-form">
        <input type="submit" id="auto-submit-button" />
    </form>
</#macro>

<#macro sectionBlock title content>
    <div class="section-block">
        <h2>${title}</h2>
        <p>${content}</p>
    </div>
</#macro>

<#macro stepIndicator step currentStep>
    <#if step == currentStep>
        <span class="step active">${step}</span>
    <#elseif step < currentStep>
        <span class="step completed">${step}</span>
    <#else>
        <span class="step">${step}</span>
    </#if>
</#macro>

<#macro verificationHeader title>
    <div class="ssi-auth-container">
        <h1>${title}</h1>
    </div>
</#macro>

<#macro verificationInstructions instructions>
    <p class="subtitle">${instructions}</p>
</#macro>
