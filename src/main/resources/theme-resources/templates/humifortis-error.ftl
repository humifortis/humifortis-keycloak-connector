<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("errorTitle","Authentication Error")}
    <#elseif section = "form">
        <div class="alert alert-error" role="alert">
            <span class="${properties.kcFeedbackErrorIcon!}"></span>
            <p class="kc-feedback-text">
                <strong>${msg(hfErrorMessageKey!"hf.error.internal_error")}</strong>
            </p>
            <#if hfErrorDetailKey??>
                <p class="pf-u-font-size-sm pf-u-color-200">
                    ${msg(hfErrorDetailKey)}
                </p>
            </#if>
            <#if hfErrorCode??>
                <p class="text-muted small">
                    ${msg("errorReference","Reference")}: <code>${hfErrorCode}</code>
                    <#if hfTimestamp??> &mdash; ${hfTimestamp?substring(0, 19)?replace("T", " ")} UTC</#if>
                </p>
            </#if>
            <p>
                ${msg("errorContactSupport","If you believe this is an error, please contact your administrator.")}
            </p>
        </div>
        <div class="${properties.kcFormGroupClass!}">
            <a href="${url.loginRestartFlowUrl}" class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!}">
                ${msg("doTryAgain","Try Again")}
            </a>
        </div>
    </#if>
</@layout.registrationLayout>
