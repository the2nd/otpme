(function () {
    'use strict';

    function base64urlToBuffer(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padding = '='.repeat((4 - base64.length % 4) % 4);
        const binary = atob(base64 + padding);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function bufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (const byte of bytes) {
            binary += String.fromCharCode(byte);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    async function fido2Login() {
        const pageData = document.getElementById('page-data').dataset;
        const beginUrl = pageData.urlFido2Begin;
        const completeUrl = pageData.urlFido2Complete;

        const statusEl = document.getElementById('fido2Status');
        const errorEl = document.getElementById('fido2Error');
        const username = document.getElementById('username').value;
        statusEl.textContent = '';
        errorEl.textContent = '';

        if (!username) {
            errorEl.textContent = 'Please enter your username first.';
            return;
        }

        if (!window.isSecureContext) {
            errorEl.textContent = 'WebAuthn requires HTTPS. Please access this page via HTTPS.';
            return;
        }

        if (!window.PublicKeyCredential) {
            errorEl.textContent = 'WebAuthn is not supported in this browser.';
            return;
        }

        const btn = document.getElementById('fido2LoginBtn');
        btn.disabled = true;
        statusEl.textContent = 'Requesting authentication challenge...';

        try {
            const beginResp = await fetch(beginUrl, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username: username}),
            });
            if (!beginResp.ok) {
                const err = await beginResp.json();
                throw new Error(err.error || 'Failed to start authentication.');
            }
            const options = await beginResp.json();

            const publicKey = options.publicKey;
            publicKey.challenge = base64urlToBuffer(publicKey.challenge);
            if (publicKey.allowCredentials) {
                publicKey.allowCredentials = publicKey.allowCredentials.map(cred => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id),
                }));
            }

            statusEl.textContent = 'Please touch your security key...';
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

            statusEl.textContent = 'Verifying...';
            const completeResp = await fetch(completeUrl, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(authResponse),
            });
            if (!completeResp.ok) {
                const err = await completeResp.json();
                throw new Error(err.error || 'Authentication failed.');
            }
            const result = await completeResp.json();

            statusEl.textContent = 'Login successful! Redirecting...';
            window.location.href = result.redirect;
        } catch (e) {
            errorEl.textContent = e.message || 'Authentication failed.';
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
