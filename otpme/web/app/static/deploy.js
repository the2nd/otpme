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

    // Types the user gives a name to before anything is created. It is
    // what the token is called once the SSO role moves to another one,
    // so it has to exist by then -- and asking afterwards is not an
    // option, the user is somewhere else entirely at that point.
    // Mirrors DEVICE_NAME_TOKEN_TYPES in sso1.py.
    const DEVICE_NAME_TYPES = ['tiqr', 'fido2', 'totp'];
    // Which type the name step is collecting for.
    let pendingTokenType = null;

    function showDeviceNameStep(tokenType) {
        const i18n = getI18n();
        pendingTokenType = tokenType;
        const input = document.getElementById('deployDeviceName');
        input.placeholder = (tokenType === 'fido2'
                ? (i18n.placeholderKeyName || 'e.g. my security key')
                : (i18n.placeholderDeviceName || 'e.g. my phone'));
        document.getElementById('step-start').classList.add('is-hidden');
        document.getElementById('step-device-name').classList.remove('is-hidden');
        input.focus();
    }

    async function startDeploy(tokenType, deviceName) {
        const urls = getUrls();
        const i18n = getI18n();
        const statusEl = document.getElementById('deployStatus');
        const errorEl = document.getElementById('deployError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        // A phone or a security key needs its name before anything can
        // start. Ask for it first, then come back here with it.
        if (DEVICE_NAME_TYPES.includes(tokenType) && !deviceName) {
            showDeviceNameStep(tokenType);
            return;
        }

        document.querySelectorAll('#step-start button').forEach(b => b.disabled = true);
        statusEl.textContent = i18n.labelCreatingToken || 'Creating token...';

        const beginBody = {token_type: tokenType};
        if (deviceName) beginBody.device_name = deviceName;
        try {
            const resp = await fetchJSON(urls.urlDeployBegin, {
                method: 'POST',
                    body: JSON.stringify(beginBody),
            });
            const result = await resp.json();
            if (!resp.ok) {
                // deploy_login_token_reauth: what comes out of this
                // flow replaces the token the user signs in with, so
                // the server wants a fresh proof first. Send them
                // through /reauth and back to this page, where they
                // start again -- there is nothing to resume, nothing
                // was created yet.
                if (result.step_up_required) {
                    window.location.assign(urls.urlReauth + '?next='
                            + encodeURIComponent(urls.deployPath || '/deploy'));
                    return;
                }
                throw new Error(result.error || i18n.labelDeploymentFailed || 'Deployment failed.');
            }

            if (result.token_type === 'fido2') {
                document.getElementById('step-device-name').classList.add('is-hidden');
                await deployFido2();
            } else if (result.token_type === 'tiqr') {
                document.getElementById('step-start').classList.add('is-hidden');
                document.getElementById('step-device-name').classList.add('is-hidden');
                document.getElementById('step-tiqr').classList.remove('is-hidden');
                document.getElementById('tiqrDeployQrcodeImg').src = result.qrcode_img;
                // The code only. enroll_url is deliberately not put
                // into a link -- see the comment in deploy.html.
                statusEl.textContent = i18n.labelWaitingPhone || 'Waiting for your phone...';
                pollTiqrDeploy();
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
            // The name step hid step-start on the way in, and the
            // FIDO2 branch hides itself before the WebAuthn prompt --
            // a cancelled prompt would otherwise leave the page with
            // an error and nothing to press. Put the step back, with
            // what the user typed still in it.
            if (pendingTokenType) {
                document.getElementById('step-device-name').classList.remove('is-hidden');
            }
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

    // tiqr has nothing for the user to type: the phone answers on its
    // own connection, and the deploy is finished by calling verify
    // until the staging token exists. Same short-poll shape as the
    // login page.
    function pollTiqrDeploy() {
        const urls = getUrls();
        const i18n = getI18n();
        const statusEl = document.getElementById('deployStatus');
        const errorEl = document.getElementById('deployError');
        // The enrollment grant lives for tiqr_enrollment_expiry (five
        // minutes by default); give up a little after that.
        const deadline = Date.now() + 330000;

        async function tick() {
            if (Date.now() > deadline) {
                statusEl.textContent = '';
                errorEl.textContent = i18n.labelTiqrExpired || 'The code expired. Please try again.';
                return;
            }
            try {
                const resp = await fetchJSON(urls.urlDeployVerify, {
                    method: 'POST',
                    body: JSON.stringify({}),
                });
                const result = await resp.json();
                if (resp.ok) {
                    statusEl.textContent = (result.message || '') + ' Redirecting...';
                    document.getElementById('step-tiqr').classList.add('is-hidden');
                    setTimeout(() => {
                        window.location.href = result.redirect;
                    }, 1500);
                    return;
                }
            } catch (e) {
                // Still waiting, or a hiccup. Either way, try again.
            }
            setTimeout(tick, 2000);
        }

        setTimeout(tick, 2000);
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
        // tiqr and FIDO2 ask for the name first, then come back into
        // startDeploy with it and the type they were started for.
        const nameStartBtn = document.getElementById('deployDeviceNameBtn');
        if (nameStartBtn) {
            nameStartBtn.addEventListener('click', function () {
                const i18n = getI18n();
                const nameEl = document.getElementById('deployDeviceName');
                const deviceName = nameEl.value.trim();
                if (!deviceName) {
                    document.getElementById('deployError').textContent =
                        (pendingTokenType === 'fido2'
                            ? (i18n.labelNeedKeyName || 'Please enter a name for your security key.')
                            : (i18n.labelNeedDeviceName || 'Please enter a name for your phone.'));
                    return;
                }
                startDeploy(pendingTokenType, deviceName);
            });
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
