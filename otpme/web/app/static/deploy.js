(function () {
    'use strict';

    function getUrls() {
        return document.getElementById('page-data').dataset;
    }

    function getI18n() {
        const el = document.getElementById('page-i18n');
        return el ? el.dataset : {};
    }

    const {base64urlToBuffer, bufferToBase64url} = window.WebAuthnUtils;

    async function startDeploy(tokenType) {
        const urls = getUrls();
        const i18n = getI18n();
        const statusEl = document.getElementById('deployStatus');
        const errorEl = document.getElementById('deployError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        document.querySelectorAll('#step-start button').forEach(b => b.disabled = true);
        statusEl.textContent = i18n.labelCreatingToken || 'Creating token...';

        try {
            const resp = await fetchJSON(urls.urlDeployBegin, {
                method: 'POST',
                    body: JSON.stringify({token_type: tokenType}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelDeploymentFailed || 'Deployment failed.');
            }

            if (result.token_type === 'fido2') {
                await deployFido2();
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
        const statusEl = document.getElementById('deployStatus');

        if (!window.isSecureContext) {
            throw new Error(i18n.labelHttpsRequired || 'WebAuthn requires HTTPS.');
        }
        if (!window.PublicKeyCredential) {
            throw new Error(i18n.labelWebauthnUnsupported || 'WebAuthn is not supported in this browser.');
        }

        statusEl.textContent = i18n.labelPreparingKey || 'Preparing security key registration...';
        const beginResp = await fetchJSON(urls.urlFido2RegisterBegin, {
            method: 'POST',
            body: JSON.stringify({}),
        });
        if (!beginResp.ok) {
            const err = await beginResp.json();
            throw new Error(err.error || i18n.labelFailedStartReg || 'Failed to start registration.');
        }
        const options = await beginResp.json();

        const publicKey = options.publicKey;
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
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
            },
            clientExtensionResults: credential.getClientExtensionResults(),
        };

        statusEl.textContent = i18n.labelCompletingReg || 'Completing registration...';
        const completeResp = await fetchJSON(urls.urlFido2RegisterComplete, {
            method: 'POST',
            body: JSON.stringify(regResponse),
        });
        if (!completeResp.ok) {
            const err = await completeResp.json();
            throw new Error(err.error || i18n.labelRegFailed || 'Registration failed.');
        }

        statusEl.textContent = i18n.labelFinalizing || 'Finalizing deployment...';
        const verifyResp = await fetchJSON(urls.urlDeployVerify, {
            method: 'POST',
            body: JSON.stringify({}),
        });
        const verifyResult = await verifyResp.json();
        if (!verifyResp.ok) {
            throw new Error(verifyResult.error || i18n.labelDeploymentFailed || 'Deployment failed.');
        }
        statusEl.textContent = verifyResult.message + ' Redirecting...';
        document.getElementById('step-start').classList.add('is-hidden');
        setTimeout(() => {
            window.location.href = verifyResult.redirect;
        }, 1500);
    }

    async function verifyOtp() {
        const urls = getUrls();
        const i18n = getI18n();
        const statusEl = document.getElementById('deployStatus');
        const errorEl = document.getElementById('deployError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const otp = document.getElementById('otpInput').value.trim();
        if (!otp) {
            errorEl.textContent = i18n.labelNeedOtp || 'Please enter the OTP from your authenticator app.';
            return;
        }

        const btn = document.getElementById('verifyBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelVerifyingOtp || 'Verifying OTP...';

        try {
            const resp = await fetchJSON(urls.urlDeployVerify, {
                method: 'POST',
                    body: JSON.stringify({otp: otp}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelVerifyFailed || 'Verification failed.');
            }

            statusEl.textContent = result.message + ' Redirecting...';
            setTimeout(() => {
                window.location.href = result.redirect;
            }, 1500);
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelVerifyFailed || 'Verification failed.';
            statusEl.textContent = '';
            btn.disabled = false;
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        // Wire token-choice buttons (each carries data-token-type).
        document.querySelectorAll('.token-choice-btn').forEach(btn => {
            btn.addEventListener('click', () => startDeploy(btn.dataset.tokenType));
        });
        const singleBtn = document.getElementById('deployBtn');
        if (singleBtn) {
            singleBtn.addEventListener('click', () => startDeploy(singleBtn.dataset.tokenType));
        }
        const verifyBtn = document.getElementById('verifyBtn');
        if (verifyBtn) {
            verifyBtn.addEventListener('click', verifyOtp);
        }
        const otpInput = document.getElementById('otpInput');
        if (otpInput) {
            otpInput.addEventListener('keypress', function (e) {
                if (e.key === 'Enter') verifyOtp();
            });
        }
    });
})();
