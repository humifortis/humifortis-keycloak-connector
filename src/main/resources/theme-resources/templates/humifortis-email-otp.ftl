<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "header">
        ${msg("emailOtpTitle","Email Verification")}
    <#elseif section = "form">
        <form id="kc-otp-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="email_otp" class="${properties.kcLabelClass!}">
                        ${msg("emailOtpLabel","Enter the 6-digit code sent to")} ${email!}
                    </label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input id="email_otp" name="email_otp" type="text"
                           autocomplete="one-time-code" inputmode="numeric"
                           pattern="[0-9]{6}" maxlength="6" required autofocus
                           class="${properties.kcInputClass!}"
                           aria-label="${msg('emailOtpLabel','6-digit code')}"/>
                </div>
            </div>

            <#if errorCode??>
                <div class="${properties.kcFormGroupClass!} has-error">
                    <span class="${properties.kcInputErrorMessageClass!}" id="input-error-otp" aria-live="polite">
                        ${errorCode!} &mdash; ${msg("invalidEmailOtp","Invalid or expired code")}
                        <#if remainingAttempts?? && remainingAttempts gt 0>
                            (${remainingAttempts} ${msg("attemptsRemaining","attempt(s) remaining")})
                        </#if>
                    </span>
                </div>
            </#if>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                           name="login" id="kc-login" type="submit"
                           value="${msg('doVerify','Verify')}"/>
                </div>
            </div>

            <#if expirySeconds??>
                <p class="text-muted small text-center">
                    ${msg("codeExpiresIn","Code expires in")} <strong id="hf-countdown">${expirySeconds}</strong>s
                </p>
                <script>
                (function(){
                    var s=${expirySeconds};
                    var el=document.getElementById('hf-countdown');
                    if(!el) return;
                    var t=setInterval(function(){
                        s--;
                        if(el) el.textContent=s;
                        if(s<=0){ clearInterval(t); if(el) el.textContent='0 — '+${msg("codeExpired","expired")}; }
                    },1000);
                })();
                </script>
            </#if>
        </form>
    </#if>
</@layout.registrationLayout>
