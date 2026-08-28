(function () {
    'use strict';

    function getUrls() { return document.getElementById('page-data').dataset; }
    function getI18n() {
        const el = document.getElementById('page-i18n');
        return el ? el.dataset : {};
    }

    const {base64urlToBuffer, bufferToBase64url} = window.WebAuthnUtils;

    function recoveryContext() {
        const data = getUrls();
        return {
            username: data.recoveryUsername,
            token:    data.recoveryToken,
        };
    }

    async function startDeploy(tokenType) {
        const urls = getUrls();
        const i18n = getI18n();
        const ctx = recoveryContext();
        const statusEl = document.getElementById('deployStatus');
        const errorEl = document.getElementById('deployError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        document.querySelectorAll('#step-start button').forEach(b => b.disabled = true);
        statusEl.textContent = i18n.labelCreatingToken || 'Creating token...';

        try {
            const resp = await fetchJSON(urls.urlBegin, {
                method: 'POST',
                body: JSON.stringify({
                    username:       ctx.username,
                    recovery_token: ctx.token,
                    token_type:     tokenType,
                }),
            });
            const {body: result, error} = await window.readJsonResponse(
                resp, i18n.labelDeploymentFailed || 'Deployment failed.');
            if (error) throw new Error(error);

            if (tokenType === 'fido2') {
                await deployFido2();
            } else if (tokenType === 'password') {
                // No server-side setup material to render -- straight to
                // the new-password form. verify submits the password.
                document.getElementById('step-start').classList.add('is-hidden');
                document.getElementById('step-password').classList.remove('is-hidden');
                statusEl.textContent = '';
                document.getElementById('newPasswordInput').focus();
            } else {
                document.getElementById('step-start').classList.add('is-hidden');
                document.getElementById('step-qrcode').classList.remove('is-hidden');
                document.getElementById('qrcodeImg').src = result.qrcode_img;
                document.getElementById('pinDisplay').textContent = result.pin;
                document.getElementById('secretDisplay').textContent = result.secret;
                statusEl.textContent = i18n.labelScanQr || 'Scan the QR code, then enter the OTP below.';
            }
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelDeploymentFailed || 'Deployment failed.';
            statusEl.textContent = '';
            document.querySelectorAll('#step-start button').forEach(b => b.disabled = false);
        }
    }

    async function deployFido2() {
        const urls = getUrls();
        const i18n = getI18n();
        const ctx = recoveryContext();
        const statusEl = document.getElementById('deployStatus');

        if (!window.isSecureContext) {
            throw new Error(i18n.labelHttpsRequired || 'WebAuthn requires HTTPS.');
        }
        if (!window.PublicKeyCredential) {
            throw new Error(i18n.labelWebauthnUnsupported || 'WebAuthn is not supported in this browser.');
        }

        statusEl.textContent = i18n.labelPreparingKey || 'Preparing security key registration...';
        const beginResp = await fetchJSON(urls.urlFido2Begin, {
            method: 'POST',
            body: JSON.stringify({
                username:       ctx.username,
                recovery_token: ctx.token,
            }),
        });
        const {body: options, error: beginErr} = await window.readJsonResponse(
            beginResp, i18n.labelFailedStartReg || 'Failed to start registration.');
        if (beginErr) throw new Error(beginErr);

        const publicKey = options.create_options.publicKey;
        publicKey.challenge = base64urlToBuffer(publicKey.challenge);
        publicKey.user.id = base64urlToBuffer(publicKey.user.id);
        if (publicKey.excludeCredentials) {
            publicKey.excludeCredentials = publicKey.excludeCredentials.map(cred => ({
                ...cred,
                id: base64urlToBuffer(cred.id),
            }));
        }

        statusEl.textContent = i18n.labelTouchKey || 'Please touch your security key...';
        const credential = await navigator.credentials.create({publicKey: publicKey});

        const regResponse = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON:    bufferToBase64url(credential.response.clientDataJSON),
            },
            clientExtensionResults: credential.getClientExtensionResults(),
        };

        statusEl.textContent = i18n.labelCompletingReg || 'Completing registration...';
        const completeResp = await fetchJSON(urls.urlFido2Complete, {
            method: 'POST',
            body: JSON.stringify({
                username:          ctx.username,
                recovery_token:    ctx.token,
                fido2_state_id:    options.fido2_state_id,
                registration_data: regResponse,
            }),
        });
        const {error: completeErr} = await window.readJsonResponse(
            completeResp, i18n.labelRegFailed || 'Registration failed.');
        if (completeErr) throw new Error(completeErr);

        statusEl.textContent = i18n.labelFinalizing || 'Finalizing deployment...';
        await runVerify({});
    }

    async function verifyOtp() {
        const i18n = getI18n();
        const statusEl = document.getElementById('deployStatus');
        const errorEl = document.getElementById('deployError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const otp = (document.getElementById('otpInput').value || '').trim();
        if (!otp) {
            errorEl.textContent = i18n.labelNeedOtp || 'Please enter the OTP from your authenticator app.';
            return;
        }
        const btn = document.getElementById('verifyBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelVerifyingOtp || 'Verifying OTP...';
        try {
            await runVerify({otp: otp});
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelVerifyFailed || 'Verification failed.';
            statusEl.textContent = '';
            btn.disabled = false;
        }
    }

    async function savePassword() {
        const i18n = getI18n();
        const statusEl = document.getElementById('deployStatus');
        const errorEl = document.getElementById('deployError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const pw = document.getElementById('newPasswordInput').value || '';
        const confirm = document.getElementById('newPasswordConfirmInput').value || '';
        if (!pw) {
            errorEl.textContent = i18n.labelNeedPassword || 'Please enter a new password.';
            return;
        }
        if (pw !== confirm) {
            errorEl.textContent = i18n.labelPasswordMismatch || 'Passwords do not match.';
            return;
        }
        const btn = document.getElementById('savePasswordBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelSavingPassword || 'Setting new password...';
        try {
            await runVerify({token_type: 'password', password: pw, password_confirm: confirm});
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelVerifyFailed || 'Verification failed.';
            statusEl.textContent = '';
            btn.disabled = false;
        }
    }

    async function runVerify(tokenData) {
        const urls = getUrls();
        const i18n = getI18n();
        const ctx = recoveryContext();
        const statusEl = document.getElementById('deployStatus');

        const resp = await fetchJSON(urls.urlVerify, {
            method: 'POST',
            body: JSON.stringify({
                username:       ctx.username,
                recovery_token: ctx.token,
                token_data:     tokenData,
            }),
        });
        const {body: result, error} = await window.readJsonResponse(
            resp, i18n.labelVerifyFailed || 'Verification failed.');
        if (error) throw new Error(error);

        statusEl.textContent = (result.message || '')
                + ' ' + (i18n.labelFinalizing || 'Redirecting...');
        setTimeout(() => {
            window.location.href = result.redirect;
        }, 1500);
    }

    document.addEventListener('DOMContentLoaded', function () {
        // Multi-type case: one button per allowed type, each carries
        // data-token-type. Single-type case: #deployBtn also carries
        // data-token-type.
        document.querySelectorAll('.token-choice-btn').forEach(btn => {
            btn.addEventListener('click', () => startDeploy(btn.dataset.tokenType));
        });
        const singleBtn = document.getElementById('deployBtn');
        if (singleBtn) {
            singleBtn.addEventListener('click', () => startDeploy(singleBtn.dataset.tokenType));
        }
        const verifyBtn = document.getElementById('verifyBtn');
        if (verifyBtn) verifyBtn.addEventListener('click', verifyOtp);
        const otpInput = document.getElementById('otpInput');
        if (otpInput) {
            otpInput.addEventListener('keypress', function (e) {
                if (e.key === 'Enter') verifyOtp();
            });
        }
        const savePasswordBtn = document.getElementById('savePasswordBtn');
        if (savePasswordBtn) savePasswordBtn.addEventListener('click', savePassword);
        const pwConfirmInput = document.getElementById('newPasswordConfirmInput');
        if (pwConfirmInput) {
            pwConfirmInput.addEventListener('keypress', function (e) {
                if (e.key === 'Enter') savePassword();
            });
        }
    });
})();
