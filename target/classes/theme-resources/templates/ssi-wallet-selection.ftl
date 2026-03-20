<#import "template.ftl" as layout>
<#import "ssi-components.ftl" as comp>

<@layout.registrationLayout displayInfo=false; section>

<#if section == "header">
    <h5 class="header-title">
        ${msg("ssiAuthTitle", realm.displayName)}
    </h5>

<#elseif section == "form">
    <link href="${url.resourcesPath}/ssi-auth.css" rel="stylesheet" />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">

    <div class="form-container">
        <form id="kc-ssi-auth-form" action="${url.loginAction}" method="post">
            <@comp.sectionBlock 
                title=msg("ssiAuthWalletSelection")
                content=msg("ssiAuthWalletInstruction")
            />

            <div class="section-block">
                <div class="wallet-grid">
                    <@comp.walletOption 
                        value="ACA_PY"
                        label=msg("ssiAuthWalletACAPY")
                        icon="smartphone"
                    />
                    <@comp.walletOption 
                        value="WALT_ID"
                        label=msg("ssiAuthWalletWaltId")
                        icon="shield"
                    />
                </div>
            </div>
        </form>
    </div>

<#elseif section == "info">
    <div class="info-text">
        <p>${msg("ssiAuthInstruction")}</p>
    </div>
</#if>

</@layout.registrationLayout>
