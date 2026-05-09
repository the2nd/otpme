(function () {
    'use strict';

    function getUrls() {
        return document.getElementById('page-data').dataset;
    }

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

    async function startDeploy(tokenType) {
        const urls = getUrls();
        const statusEl = document.getElementById('deployStatus');
        const errorEl = document.getElementById('deployError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        document.querySelectorAll('#step-start button').forEach(b => b.disabled = true);
        statusEl.textContent = 'Creating token...';

        try {
            const resp = await fetch(urls.urlDeployBegin, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({token_type: tokenType}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || 'Deployment failed.');
            }

            if (result.token_type === 'fido2') {
                await deployFido2();
            } else {
                document.getElementById('step-start').style.display = 'none';
                document.getElementById('step-qrcode').style.display = 'block';
                document.getElementById('qrcodeImg').src = result.qrcode_img;
                document.getElementById('pinDisplay').textContent = result.pin;
                document.getElementById('secretDisplay').textContent = result.secret;
                statusEl.textContent = 'Scan the QR code, then enter the OTP below.';
            }
        } catch (e) {
            errorEl.textContent = e.message || 'Deployment failed.';
            statusEl.textContent = '';
            document.querySelectorAll('#step-start button').forEach(b => b.disabled = false);
        }
    }

    async function deployFido2() {
        const urls = getUrls();
        const statusEl = document.getElementById('deployStatus');

        if (!window.isSecureContext) {
            throw new Error('WebAuthn requires HTTPS.');
        }
        if (!window.PublicKeyCredential) {
            throw new Error('WebAuthn is not supported in this browser.');
        }

        statusEl.textContent = 'Preparing security key registration...';
        const beginResp = await fetch(urls.urlFido2RegisterBegin, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({}),
        });
        if (!beginResp.ok) {
            const err = await beginResp.json();
            throw new Error(err.error || 'Failed to start registration.');
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

        statusEl.textContent = 'Please touch your security key...';
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

        statusEl.textContent = 'Completing registration...';
        const completeResp = await fetch(urls.urlFido2RegisterComplete, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(regResponse),
        });
        if (!completeResp.ok) {
            const err = await completeResp.json();
            throw new Error(err.error || 'Registration failed.');
        }

        statusEl.textContent = 'Finalizing deployment...';
        const verifyResp = await fetch(urls.urlDeployVerify, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({}),
        });
        const verifyResult = await verifyResp.json();
        if (!verifyResp.ok) {
            throw new Error(verifyResult.error || 'Deployment failed.');
        }
        statusEl.textContent = verifyResult.message + ' Redirecting...';
        document.getElementById('step-start').style.display = 'none';
        setTimeout(() => {
            window.location.href = verifyResult.redirect;
        }, 1500);
    }

    async function verifyOtp() {
        const urls = getUrls();
        const statusEl = document.getElementById('deployStatus');
        const errorEl = document.getElementById('deployError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const otp = document.getElementById('otpInput').value.trim();
        if (!otp) {
            errorEl.textContent = 'Please enter the OTP from your authenticator app.';
            return;
        }

        const btn = document.getElementById('verifyBtn');
        btn.disabled = true;
        statusEl.textContent = 'Verifying OTP...';

        try {
            const resp = await fetch(urls.urlDeployVerify, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({otp: otp}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || 'Verification failed.');
            }

            statusEl.textContent = result.message + ' Redirecting...';
            setTimeout(() => {
                window.location.href = result.redirect;
            }, 1500);
        } catch (e) {
            errorEl.textContent = e.message || 'Verification failed.';
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
