// Shared WebAuthn helpers.
//
// python-fido2 / py_webauthn serialize the binary fields (challenge,
// user.id, credential id, signatures, attestationObject, etc.) as
// base64url strings, but the browser WebAuthn API takes/returns
// ArrayBuffers. These two helpers bridge that gap and used to be
// duplicated verbatim in login.js / deploy.js / settings.js.

(function () {
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

    window.WebAuthnUtils = {
        base64urlToBuffer: base64urlToBuffer,
        bufferToBase64url: bufferToBase64url,
    };
})();
