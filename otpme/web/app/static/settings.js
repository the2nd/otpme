(function () {
    'use strict';

    function getUrls() {
        return document.getElementById('page-data').dataset;
    }

    async function changePassword() {
        const urls = getUrls();
        const statusEl = document.getElementById('pwStatus');
        const errorEl = document.getElementById('pwError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const currentPassword = document.getElementById('currentPassword').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (!currentPassword || !newPassword || !confirmPassword) {
            errorEl.textContent = 'All fields are required.';
            return;
        }
        if (newPassword !== confirmPassword) {
            errorEl.textContent = 'New passwords do not match.';
            return;
        }

        const btn = document.getElementById('changePwBtn');
        btn.disabled = true;
        statusEl.textContent = 'Changing password...';

        try {
            const resp = await fetch(urls.urlChangePassword, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword,
                    confirm_password: confirmPassword,
                }),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || 'Password change failed.');
            }
            statusEl.textContent = result.message || 'Password changed successfully.';
            document.getElementById('currentPassword').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('confirmPassword').value = '';
        } catch (e) {
            errorEl.textContent = e.message || 'Password change failed.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    async function changePin() {
        const urls = getUrls();
        const statusEl = document.getElementById('pinStatus');
        const errorEl = document.getElementById('pinError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const currentPin = document.getElementById('currentPin').value;
        const newPin = document.getElementById('newPin').value;
        const confirmPin = document.getElementById('confirmPin').value;

        if (!currentPin || !newPin || !confirmPin) {
            errorEl.textContent = 'All fields are required.';
            return;
        }
        if (newPin !== confirmPin) {
            errorEl.textContent = 'New PINs do not match.';
            return;
        }

        const btn = document.getElementById('changePinBtn');
        btn.disabled = true;
        statusEl.textContent = 'Changing PIN...';

        try {
            const resp = await fetch(urls.urlChangePin, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    current_pin: currentPin,
                    new_pin: newPin,
                    confirm_pin: confirmPin,
                }),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || 'PIN change failed.');
            }
            statusEl.textContent = result.message || 'PIN changed successfully.';
            document.getElementById('currentPin').value = '';
            document.getElementById('newPin').value = '';
            document.getElementById('confirmPin').value = '';
        } catch (e) {
            errorEl.textContent = e.message || 'PIN change failed.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    async function loadDeviceTokens() {
        const urls = getUrls();
        const listEl = document.getElementById('deviceTokenList');
        listEl.innerHTML = '';
        try {
            const resp = await fetch(urls.urlListDeviceTokens);
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || 'Failed to load device tokens.');
            }
            const roleInfoEl = document.getElementById('deviceRoleInfo');
            roleInfoEl.textContent = result.role_info || '';
            roleInfoEl.style.display = result.role_info ? '' : 'none';
            const roleConfigured = !!result.role_configured;
            const addForm = document.getElementById('deviceAddForm');
            const disabledHint = document.getElementById('deviceDisabledHint');
            const nameInput = document.getElementById('deviceName');
            const addBtn = document.getElementById('addDeviceBtn');
            if (roleConfigured) {
                addForm.style.display = '';
                disabledHint.style.display = 'none';
                nameInput.disabled = false;
                addBtn.disabled = false;
            } else {
                addForm.style.display = 'none';
                disabledHint.style.display = '';
                nameInput.disabled = true;
                addBtn.disabled = true;
            }
            const tokens = result.device_tokens || [];
            if (tokens.length === 0) {
                const li = document.createElement('li');
                li.className = 'empty';
                li.textContent = 'No device tokens yet.';
                listEl.appendChild(li);
                return;
            }
            for (const t of tokens) {
                const li = document.createElement('li');
                const label = document.createElement('span');
                label.className = 'device-label';
                label.textContent = t.device_name || t.name;
                li.appendChild(label);
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-secondary btn-small';
                btn.textContent = 'Delete';
                btn.addEventListener('click', () => deleteDeviceToken(t.name, t.device_name || t.name));
                li.appendChild(btn);
                listEl.appendChild(li);
            }
        } catch (e) {
            const li = document.createElement('li');
            li.className = 'error-msg';
            li.textContent = e.message || 'Failed to load device tokens.';
            listEl.appendChild(li);
        }
    }

    async function addDeviceToken() {
        const urls = getUrls();
        const statusEl = document.getElementById('deviceStatus');
        const errorEl = document.getElementById('deviceError');
        const resultEl = document.getElementById('deviceResult');
        statusEl.textContent = '';
        errorEl.textContent = '';
        resultEl.style.display = 'none';

        const deviceName = document.getElementById('deviceName').value.trim();
        if (!deviceName) {
            errorEl.textContent = 'Device name is required.';
            return;
        }

        const btn = document.getElementById('addDeviceBtn');
        btn.disabled = true;
        statusEl.textContent = 'Adding device token...';

        try {
            const resp = await fetch(urls.urlAddDeviceToken, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({device_name: deviceName}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || 'Failed to add device token.');
            }
            statusEl.textContent = 'Device token created.';
            document.getElementById('devicePassword').textContent = result.password || '';
            resultEl.style.display = 'block';
            document.getElementById('deviceName').value = '';
            loadDeviceTokens();
        } catch (e) {
            errorEl.textContent = e.message || 'Failed to add device token.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    async function deleteDeviceToken(name, label) {
        const urls = getUrls();
        if (!confirm('Delete device token "' + label + '"?')) {
            return;
        }
        const statusEl = document.getElementById('deviceStatus');
        const errorEl = document.getElementById('deviceError');
        errorEl.textContent = '';
        try {
            const resp = await fetch(urls.urlDelDeviceToken, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name: name}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || 'Failed to delete device token.');
            }
            const resultEl = document.getElementById('deviceResult');
            resultEl.style.display = 'none';
            document.getElementById('devicePassword').textContent = '';
            statusEl.textContent = 'Device token deleted.';
            loadDeviceTokens();
        } catch (e) {
            errorEl.textContent = e.message || 'Failed to delete device token.';
        }
    }

    async function copyDevicePassword() {
        const pw = document.getElementById('devicePassword').textContent;
        if (!pw) return;
        try {
            await navigator.clipboard.writeText(pw);
            document.getElementById('deviceStatus').textContent = 'Password copied to clipboard.';
        } catch (e) {
            document.getElementById('deviceError').textContent = 'Failed to copy password.';
        }
    }

    function getConsentUrls() {
        const el = document.getElementById('oidc-consent-urls');
        return el ? el.dataset : null;
    }

    function formatGrantedAt(ts) {
        if (!ts) return '';
        try {
            return new Date(ts * 1000).toLocaleString();
        } catch (e) {
            return '';
        }
    }

    async function loadOidcConsents() {
        const urls = getConsentUrls();
        const listEl = document.getElementById('oidcConsentList');
        if (!urls || !listEl) return;
        listEl.innerHTML = '';
        try {
            const resp = await fetch(urls.urlList);
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || 'Failed to load consents.');
            }
            const consents = result.consents || [];
            if (consents.length === 0) {
                const li = document.createElement('li');
                li.className = 'empty';
                li.textContent = 'No connected applications.';
                listEl.appendChild(li);
                return;
            }
            for (const c of consents) {
                const li = document.createElement('li');
                const label = document.createElement('span');
                label.className = 'device-label';
                const head = document.createElement('strong');
                head.textContent = c.client_name;
                label.appendChild(head);
                if (c.scopes && c.scopes.length) {
                    const scopes = document.createElement('span');
                    scopes.className = 'hint';
                    scopes.style.display = 'block';
                    scopes.textContent = 'Scopes: ' + c.scopes.join(', ');
                    label.appendChild(scopes);
                }
                if (c.granted_at) {
                    const granted = document.createElement('span');
                    granted.className = 'hint';
                    granted.style.display = 'block';
                    granted.textContent = 'Granted: ' + formatGrantedAt(c.granted_at);
                    label.appendChild(granted);
                }
                li.appendChild(label);
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-secondary btn-small';
                btn.textContent = 'Disconnect';
                btn.addEventListener('click',
                        () => revokeOidcConsent(c.client_uuid, c.client_name));
                li.appendChild(btn);
                listEl.appendChild(li);
            }
        } catch (e) {
            const li = document.createElement('li');
            li.className = 'error-msg';
            li.textContent = e.message || 'Failed to load consents.';
            listEl.appendChild(li);
        }
    }

    async function revokeOidcConsent(clientUuid, label) {
        const urls = getConsentUrls();
        if (!urls) return;
        if (!confirm('Disconnect "' + label
                     + '"? Active sessions for this application will be terminated.')) {
            return;
        }
        const statusEl = document.getElementById('consentStatus');
        const errorEl = document.getElementById('consentError');
        statusEl.textContent = '';
        errorEl.textContent = '';
        try {
            const resp = await fetch(urls.urlRevoke, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({client_uuid: clientUuid}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || 'Failed to revoke consent.');
            }
            statusEl.textContent = result.message || 'Disconnected.';
            loadOidcConsents();
        } catch (e) {
            errorEl.textContent = e.message || 'Failed to revoke consent.';
        }
    }

    async function saveLanguage() {
        const urls = getUrls();
        const statusEl = document.getElementById('languageStatus');
        const errorEl = document.getElementById('languageError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const select = document.getElementById('languageSelect');
        const language = select.value;
        const btn = document.getElementById('saveLanguageBtn');
        btn.disabled = true;
        statusEl.textContent = 'Saving...';
        try {
            const resp = await fetch(urls.urlChangeLanguage, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({language: language}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || 'Failed to save language.');
            }
            // Reload so Babel re-renders the page in the new locale.
            window.location.reload();
        } catch (e) {
            errorEl.textContent = e.message || 'Failed to save language.';
            statusEl.textContent = '';
            btn.disabled = false;
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        const pwBtn = document.getElementById('changePwBtn');
        if (pwBtn) pwBtn.addEventListener('click', changePassword);

        const pinBtn = document.getElementById('changePinBtn');
        if (pinBtn) pinBtn.addEventListener('click', changePin);

        const langBtn = document.getElementById('saveLanguageBtn');
        if (langBtn) langBtn.addEventListener('click', saveLanguage);

        const addBtn = document.getElementById('addDeviceBtn');
        if (addBtn) addBtn.addEventListener('click', addDeviceToken);

        const copyBtn = document.getElementById('copyDevicePwBtn');
        if (copyBtn) copyBtn.addEventListener('click', copyDevicePassword);

        loadDeviceTokens();
        loadOidcConsents();
    });
})();
