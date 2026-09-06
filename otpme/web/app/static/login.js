(function () {
    'use strict';

    const {base64urlToBuffer, bufferToBase64url} = window.WebAuthnUtils;

    function getI18n() {
        const el = document.getElementById('page-i18n');
        return el ? el.dataset : {};
    }

    async function fido2Login() {
        const pageData = document.getElementById('page-data').dataset;
        const i18n = getI18n();
        const beginUrl = pageData.urlFido2Begin;
        const completeUrl = pageData.urlFido2Complete;

        const statusEl = document.getElementById('fido2Status');
        const errorEl = document.getElementById('fido2Error');
        const username = document.getElementById('username').value;
        statusEl.textContent = '';
        errorEl.textContent = '';

        if (!username) {
            errorEl.textContent = i18n.labelNeedUsername || 'Please enter your username first.';
            return;
        }

        if (!window.isSecureContext) {
            errorEl.textContent = i18n.labelHttpsRequired || 'WebAuthn requires HTTPS. Please access this page via HTTPS.';
            return;
        }

        if (!window.PublicKeyCredential) {
            errorEl.textContent = i18n.labelWebauthnUnsupported || 'WebAuthn is not supported in this browser.';
            return;
        }

        const btn = document.getElementById('fido2LoginBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelRequestingChallenge || 'Requesting authentication challenge...';

        try {
            const beginResp = await fetchJSON(beginUrl, {
                method: 'POST',
                body: JSON.stringify({username: username}),
            });
            const beginResult = await window.readJsonResponse(
                beginResp,
                i18n.labelFailedStart || 'Failed to start authentication.');
            if (beginResult.error) {
                throw new Error(beginResult.error);
            }
            const options = beginResult.body;

            const publicKey = options.publicKey;
            publicKey.challenge = base64urlToBuffer(publicKey.challenge);
            if (publicKey.allowCredentials) {
                publicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id),
                }));
            }

            statusEl.textContent = i18n.labelTouchKey || 'Please touch your security key...';
            const credential = await navigator.credentials.get({publicKey: publicKey});

            const authResponse = {
                id: credential.id,
                rawId: bufferToBase64url(credential.rawId),
                type: credential.type,
                response: {
                    authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                    signature: bufferToBase64url(credential.response.signature),
                },
                clientExtensionResults: credential.getClientExtensionResults(),
            };
            if (credential.response.userHandle) {
                authResponse.response.userHandle = bufferToBase64url(credential.response.userHandle);
            }

            statusEl.textContent = i18n.labelVerifying || 'Verifying...';
            const completeResp = await fetchJSON(completeUrl, {
                method: 'POST',
                body: JSON.stringify(authResponse),
            });
            const completeResult = await window.readJsonResponse(
                completeResp,
                i18n.labelAuthFailed || 'Authentication failed.');
            if (completeResult.error) {
                throw new Error(completeResult.error);
            }
            const result = completeResult.body;

            statusEl.textContent = i18n.labelLoginSuccess || 'Login successful! Redirecting...';
            window.location.href = result.redirect;
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelAuthFailed || 'Authentication failed.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    // ---- tiqr ----
    //
    // Two connections make one login: the phone answers the challenge
    // over its own, and this browser collects the result by polling.
    // The poll carries no session key -- that one is public, it is
    // printed in the QR code -- the server looks the result up under a
    // handle it put in this browser's session at begin.

    let tiqrPollTimer = null;

    function stopTiqrPolling() {
        if (tiqrPollTimer === null) return;
        clearTimeout(tiqrPollTimer);
        tiqrPollTimer = null;
    }

    // Show the QR instead of the login form, not underneath it. The
    // form has done its job once the challenge is out -- the username
    // is read, and the password field is not what finishes this login
    // -- and leaving it there pushed the code below the fold on a
    // phone, which is the one screen where the code matters most.
    //
    // The status and error lines sit outside the form on purpose, so
    // "Waiting for your phone..." stays readable while it is hidden.
    function showTiqrBox(show) {
        const box = document.getElementById('tiqrBox');
        if (box) box.classList.toggle('is-hidden', !show);
        const form = document.getElementById('loginForm');
        if (form) form.classList.toggle('is-hidden', show);
        const recoverLink = document.querySelector('.login-recover-link');
        if (recoverLink) recoverLink.classList.toggle('is-hidden', show);
    }

    async function tiqrLogin() {
        const pageData = document.getElementById('page-data').dataset;
        const i18n = getI18n();
        const statusEl = document.getElementById('fido2Status');
        const errorEl = document.getElementById('fido2Error');
        const username = document.getElementById('username').value;
        statusEl.textContent = '';
        errorEl.textContent = '';

        if (!username) {
            errorEl.textContent = i18n.labelNeedUsername || 'Please enter your username first.';
            return;
        }

        const btn = document.getElementById('tiqrLoginBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelRequestingChallenge || 'Requesting authentication challenge...';
        try {
            const resp = await fetchJSON(pageData.urlTiqrBegin, {
                method: 'POST',
                body: JSON.stringify({username: username}),
            });
            const parsed = await window.readJsonResponse(
                resp,
                i18n.labelTiqrFailed || 'Failed to start tiqr authentication.');
            if (parsed.error) {
                throw new Error(parsed.error);
            }
            const result = parsed.body;
            const img = document.getElementById('tiqrQrcodeImg');
            if (img) img.src = result.qrcode_img || '';
            // Image and button carry the same URL: scan it from another
            // device, tap it when this browser is on the phone.
            const link = document.getElementById('tiqrAuthLink');
            if (link) link.href = result.auth_url || '#';
            const openBtn = document.getElementById('tiqrOpenBtn');
            if (openBtn) openBtn.href = result.auth_url || '#';
            const hint = document.getElementById('tiqrHint');
            if (hint) {
                hint.textContent = i18n.labelTiqrScan
                        || 'Scan the code with the tiqr app, or tap it if you are on your phone.';
            }
            showTiqrBox(true);
            statusEl.textContent = i18n.labelTiqrWaiting || 'Waiting for your phone...';
            pollTiqrStatus();
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelTiqrFailed || 'Failed to start tiqr authentication.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    function pollTiqrStatus() {
        const pageData = document.getElementById('page-data').dataset;
        const i18n = getI18n();
        const statusEl = document.getElementById('fido2Status');
        const errorEl = document.getElementById('fido2Error');
        // The challenge dies after tiqr_challenge_expiry (three minutes
        // by default). Give up a little after that rather than polling
        // a page somebody walked away from.
        const deadline = Date.now() + 200000;
        stopTiqrPolling();

        function expired() {
            stopTiqrPolling();
            showTiqrBox(false);
            statusEl.textContent = '';
            errorEl.textContent = i18n.labelTiqrExpired || 'The code expired. Please try again.';
        }

        async function tick() {
            if (Date.now() > deadline) {
                expired();
                return;
            }
            try {
                const resp = await fetchJSON(pageData.urlTiqrStatus);
                const result = await resp.json();
                if (resp.ok && result.status === 'ok' && result.redirect) {
                    stopTiqrPolling();
                    statusEl.textContent = i18n.labelLoginSuccess || 'Login successful! Redirecting...';
                    window.location.href = result.redirect;
                    return;
                }
                if (resp.ok && result.status === 'challenge-expired') {
                    expired();
                    return;
                }
            } catch (e) {
                // One failed poll is not worth aborting the login over;
                // the next tick tries again.
            }
            tiqrPollTimer = setTimeout(tick, 2000);
        }

        tiqrPollTimer = setTimeout(tick, 2000);
    }

    function showTiqrOtpForm() {
        // Polling deliberately keeps running: the user may have opened
        // this by mistake and still be about to scan.
        const form = document.getElementById('tiqrOtpForm');
        if (form) form.classList.remove('is-hidden');
        const input = document.getElementById('tiqrOtp');
        if (input) input.focus();
    }

    async function tiqrSubmitOtp() {
        const pageData = document.getElementById('page-data').dataset;
        const i18n = getI18n();
        const statusEl = document.getElementById('fido2Status');
        const errorEl = document.getElementById('fido2Error');
        const response = document.getElementById('tiqrOtp').value.trim();
        errorEl.textContent = '';
        if (!response) {
            errorEl.textContent = i18n.labelTiqrOtpRequired || 'Please enter the code from your app.';
            return;
        }
        const btn = document.getElementById('tiqrOtpBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelVerifying || 'Verifying...';
        try {
            const resp = await fetchJSON(pageData.urlTiqrOtp, {
                method: 'POST',
                body: JSON.stringify({response: response}),
            });
            const parsed = await window.readJsonResponse(
                resp,
                i18n.labelAuthFailed || 'Authentication failed.');
            if (parsed.error) {
                throw new Error(parsed.error);
            }
            stopTiqrPolling();
            statusEl.textContent = i18n.labelLoginSuccess || 'Login successful! Redirecting...';
            window.location.href = parsed.body.redirect;
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelAuthFailed || 'Authentication failed.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    function cancelTiqrLogin() {
        stopTiqrPolling();
        showTiqrBox(false);
        const statusEl = document.getElementById('fido2Status');
        if (statusEl) statusEl.textContent = '';
    }

    document.addEventListener('DOMContentLoaded', function () {
        const btn = document.getElementById('fido2LoginBtn');
        if (btn) {
            btn.addEventListener('click', fido2Login);
        }
        const tiqrBtn = document.getElementById('tiqrLoginBtn');
        if (tiqrBtn) tiqrBtn.addEventListener('click', tiqrLogin);
        const manualBtn = document.getElementById('tiqrManualBtn');
        if (manualBtn) manualBtn.addEventListener('click', showTiqrOtpForm);
        const otpBtn = document.getElementById('tiqrOtpBtn');
        if (otpBtn) otpBtn.addEventListener('click', tiqrSubmitOtp);
        const cancelBtn = document.getElementById('tiqrCancelBtn');
        if (cancelBtn) cancelBtn.addEventListener('click', cancelTiqrLogin);
    });
})();
