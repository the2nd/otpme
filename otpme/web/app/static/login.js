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

    document.addEventListener('DOMContentLoaded', function () {
        const btn = document.getElementById('fido2LoginBtn');
        if (btn) {
            btn.addEventListener('click', fido2Login);
        }
    });
})();
