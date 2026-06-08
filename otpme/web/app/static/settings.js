(function () {
    'use strict';

    function getUrls() {
        return document.getElementById('page-data').dataset;
    }

    function getPageI18n() {
        const el = document.getElementById('page-i18n');
        return el ? el.dataset : {};
    }

    // Substitute {name}-style placeholders in a translated string
    // client-side. We avoid %(name)s here because Jinja-Babel's
    // gettext eagerly runs a %-format on the result and raises
    // KeyError when the template doesn't pass the substitution
    // value -- our placeholders are expanded only later, in JS, so
    // {name} is the safe carrier syntax that survives gettext.
    function interpolate(template, vars) {
        return template.replace(/\{(\w+)\}/g, (_, k) =>
                (vars[k] !== undefined ? vars[k] : ''));
    }

    async function changePassword() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const statusEl = document.getElementById('pwStatus');
        const errorEl = document.getElementById('pwError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const currentPassword = document.getElementById('currentPassword').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (!currentPassword || !newPassword || !confirmPassword) {
            errorEl.textContent = i18n.labelAllFieldsRequired || 'All fields are required.';
            return;
        }
        if (newPassword !== confirmPassword) {
            errorEl.textContent = i18n.labelNewPasswordsMismatch || 'New passwords do not match.';
            return;
        }

        const btn = document.getElementById('changePwBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelChangingPassword || 'Changing password...';

        try {
            const resp = await fetchJSON(urls.urlChangePassword, {
                method: 'POST',
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword,
                    confirm_password: confirmPassword,
                }),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelPasswordFailed || 'Password change failed.');
            }
            statusEl.textContent = result.message || i18n.labelPasswordSuccess || 'Password changed successfully.';
            document.getElementById('currentPassword').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('confirmPassword').value = '';
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelPasswordFailed || 'Password change failed.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    async function changePin() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const statusEl = document.getElementById('pinStatus');
        const errorEl = document.getElementById('pinError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const currentPin = document.getElementById('currentPin').value;
        const newPin = document.getElementById('newPin').value;
        const confirmPin = document.getElementById('confirmPin').value;

        if (!currentPin || !newPin || !confirmPin) {
            errorEl.textContent = i18n.labelAllFieldsRequired || 'All fields are required.';
            return;
        }
        if (newPin !== confirmPin) {
            errorEl.textContent = i18n.labelNewPinsMismatch || 'New PINs do not match.';
            return;
        }

        const btn = document.getElementById('changePinBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelChangingPin || 'Changing PIN...';

        try {
            const resp = await fetchJSON(urls.urlChangePin, {
                method: 'POST',
                body: JSON.stringify({
                    current_pin: currentPin,
                    new_pin: newPin,
                    confirm_pin: confirmPin,
                }),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelPinFailed || 'PIN change failed.');
            }
            statusEl.textContent = result.message || i18n.labelPinSuccess || 'PIN changed successfully.';
            document.getElementById('currentPin').value = '';
            document.getElementById('newPin').value = '';
            document.getElementById('confirmPin').value = '';
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelPinFailed || 'PIN change failed.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    function getDeviceI18n() {
        const el = document.getElementById('deviceI18n');
        return el ? el.dataset : {};
    }

    // Restrict an <input> to ``[a-z0-9-]`` live: lowercase as the user
    // types, drop everything else. Spaces/underscores become hyphens to
    // preserve word boundaries (matches the server-side sanitiser).
    // Used by both the device-token and the passkey add forms.
    function attachNameSanitizer(input) {
        if (!input || input._sanitizerAttached) return;
        input._sanitizerAttached = true;
        input.setAttribute('autocapitalize', 'off');
        input.setAttribute('autocorrect', 'off');
        input.setAttribute('spellcheck', 'false');
        input.setAttribute('pattern', '[a-z0-9-]+');
        input.addEventListener('input', () => {
            const cleaned = input.value
                .toLowerCase()
                .replace(/[ _]+/g, '-')
                .replace(/[^a-z0-9-]/g, '');
            if (cleaned !== input.value) input.value = cleaned;
        });
    }

    // One-shot reveal carried across the loadDeviceTokens() call that
    // follows a successful add. The reveal card is part of the per-role
    // card that gets fully rebuilt, so we re-inject the password into
    // the matching card during the next render and then drop the state.
    let pendingReveal = null;

    function buildRoleCard(role) {
        // One settings-card per sso_token_roles entry. The role description
        // (admin-curated, localized server-side) is shown as the section
        // hint so the user knows what the token will grant access to.
        const i18n = getDeviceI18n();
        const safeUuid = role.role_uuid.replace(/[^a-zA-Z0-9_-]/g, '');
        const ids = {
            nameInput   : `deviceName_${safeUuid}`,
            addBtn      : `addDeviceBtn_${safeUuid}`,
            status      : `deviceStatus_${safeUuid}`,
            error       : `deviceError_${safeUuid}`,
            result      : `deviceResult_${safeUuid}`,
            password    : `devicePassword_${safeUuid}`,
            copyBtn     : `copyDevicePwBtn_${safeUuid}`,
            list        : `deviceTokenList_${safeUuid}`,
        };
        const card = document.createElement('div');
        card.className = 'settings-card';
        card.dataset.roleUuid = role.role_uuid;
        const heading = `${i18n.labelDeviceTokens || 'Device Tokens'} — ${role.role_name || ''}`;
        card.innerHTML = `
            <h3></h3>
            <p class="settings-desc"></p>
            <div class="settings-form">
                <label for="${ids.nameInput}"></label>
                <input type="text" id="${ids.nameInput}" autocomplete="off">
                <button type="button" id="${ids.addBtn}" class="btn btn-primary mt-8"></button>
                <div class="status-msg" id="${ids.status}"></div>
                <div class="error-msg" id="${ids.error}"></div>
            </div>
            <div id="${ids.result}" class="device-token-reveal is-hidden">
                <div>
                    <strong></strong>
                    <code id="${ids.password}"></code>
                    <button type="button" id="${ids.copyBtn}" class="btn btn-secondary btn-small ml-8"></button>
                </div>
                <span class="hint"></span>
            </div>
            <h4></h4>
            <ul id="${ids.list}" class="device-token-list"></ul>
        `;
        card.querySelector('h3').textContent = heading;
        const descEl = card.querySelector('p.settings-desc');
        descEl.textContent = role.role_info || '';
        descEl.classList.toggle('is-hidden', !role.role_info);
        card.querySelector(`label[for="${ids.nameInput}"]`).textContent = i18n.labelDeviceName || 'Device Name';
        card.querySelector(`#${ids.nameInput}`).placeholder = i18n.labelDeviceNamePlaceholder || '';
        card.querySelector(`#${ids.addBtn}`).textContent = i18n.labelAddDeviceToken || 'Add Device Token';
        card.querySelector(`#${ids.result} strong`).textContent = i18n.labelNewPassword || 'New password:';
        card.querySelector(`#${ids.copyBtn}`).textContent = i18n.labelCopy || 'Copy';
        card.querySelector(`#${ids.result} span.hint`).textContent = i18n.labelShownOnce || '';
        card.querySelector('h4').textContent = i18n.labelExistingDeviceTokens || 'Existing Device Tokens';

        attachNameSanitizer(card.querySelector(`#${ids.nameInput}`));
        card.querySelector(`#${ids.addBtn}`).addEventListener('click',
            () => addDeviceToken(role.role_uuid, ids));
        card.querySelector(`#${ids.copyBtn}`).addEventListener('click',
            () => copyDevicePassword(ids));

        // Restore the one-shot reveal from the add that triggered this
        // render. Consumed so a subsequent unrelated reload (e.g. a
        // delete on another card) does not resurrect the password.
        if (pendingReveal && pendingReveal.role_uuid === role.role_uuid) {
            const resultEl = card.querySelector(`#${ids.result}`);
            card.querySelector(`#${ids.password}`).textContent = pendingReveal.password;
            resultEl.classList.remove('is-hidden');
            card.querySelector(`#${ids.status}`).textContent = getPageI18n().labelDeviceTokenCreated || 'Device token created.';
            pendingReveal = null;
            // Scroll the reveal into view once the card is in the DOM.
            // rAF waits for layout after the parent append in
            // loadDeviceTokens(); scrollIntoView would otherwise be a
            // no-op on the still-detached node.
            requestAnimationFrame(() => {
                resultEl.scrollIntoView({behavior: 'smooth', block: 'center'});
            });
        }

        const listEl = card.querySelector(`#${ids.list}`);
        const tokens = role.device_tokens || [];
        if (tokens.length === 0) {
            const li = document.createElement('li');
            li.className = 'empty';
            li.textContent = i18n.labelNoDeviceTokens || 'No device tokens yet.';
            listEl.appendChild(li);
        } else {
            for (const t of tokens) {
                const li = document.createElement('li');
                const label = document.createElement('span');
                label.className = 'device-label';
                label.textContent = t.device_name || t.name;
                li.appendChild(label);
                const delBtn = document.createElement('button');
                delBtn.type = 'button';
                delBtn.className = 'btn btn-secondary btn-small';
                delBtn.textContent = i18n.labelDelete || 'Delete';
                delBtn.addEventListener('click',
                    () => deleteDeviceToken(t.name, t.device_name || t.name));
                li.appendChild(delBtn);
                listEl.appendChild(li);
            }
        }
        return card;
    }

    async function loadDeviceTokens() {
        const urls = getUrls();
        const pageI18n = getPageI18n();
        const container = document.getElementById('deviceRolesContainer');
        const disabledHint = document.getElementById('deviceDisabledHint');
        container.innerHTML = '';
        try {
            const resp = await fetchJSON(urls.urlListDeviceTokens);
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || pageI18n.labelFailedLoadDeviceTokens || 'Failed to load device tokens.');
            }
            const rolesConfigured = !!result.roles_configured;
            const roles = result.roles || [];
            if (!rolesConfigured || roles.length === 0) {
                disabledHint.classList.remove('is-hidden');
                return;
            }
            disabledHint.classList.add('is-hidden');
            for (const role of roles) {
                container.appendChild(buildRoleCard(role));
            }
        } catch (e) {
            disabledHint.classList.add('is-hidden');
            const errCard = document.createElement('div');
            errCard.className = 'settings-card';
            const p = document.createElement('p');
            p.className = 'error-msg';
            p.textContent = e.message || pageI18n.labelFailedLoadDeviceTokens || 'Failed to load device tokens.';
            errCard.appendChild(p);
            container.appendChild(errCard);
        }
    }

    async function addDeviceToken(roleUuid, ids) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const statusEl = document.getElementById(ids.status);
        const errorEl = document.getElementById(ids.error);
        const resultEl = document.getElementById(ids.result);
        statusEl.textContent = '';
        errorEl.textContent = '';
        resultEl.classList.add('is-hidden');

        const deviceName = document.getElementById(ids.nameInput).value.trim();
        if (!deviceName) {
            errorEl.textContent = i18n.labelDeviceNameRequired || 'Device name is required.';
            return;
        }

        const btn = document.getElementById(ids.addBtn);
        btn.disabled = true;
        statusEl.textContent = i18n.labelAddingDeviceToken || 'Adding device token...';

        try {
            const resp = await fetchJSON(urls.urlAddDeviceToken, {
                method: 'POST',
                body: JSON.stringify({device_name: deviceName, role_uuid: roleUuid}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedAddDeviceToken || 'Failed to add device token.');
            }
            // Stash the password for the next render to pick up — the
            // current card (incl. resultEl/passwordEl/statusEl) is about
            // to be destroyed and rebuilt by loadDeviceTokens().
            pendingReveal = {role_uuid: roleUuid, password: result.password || ''};
            document.getElementById(ids.nameInput).value = '';
            loadDeviceTokens();
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelFailedAddDeviceToken || 'Failed to add device token.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    async function deleteDeviceToken(name, label) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const tpl = i18n.labelConfirmDeleteDeviceToken || 'Delete device token "%(name)s"?';
        if (!confirm(interpolate(tpl, {name: label}))) {
            return;
        }
        try {
            const resp = await fetchJSON(urls.urlDelDeviceToken, {
                method: 'POST',
                body: JSON.stringify({name: name}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedDeleteDeviceToken || 'Failed to delete device token.');
            }
            loadDeviceTokens();
        } catch (e) {
            // Reload anyway so any reveal panel is dropped; the next render
            // will surface the error context implicitly via stale state.
            loadDeviceTokens();
        }
    }

    async function copyDevicePassword(ids) {
        const pw = document.getElementById(ids.password).textContent;
        if (!pw) return;
        const i18n = getPageI18n();
        try {
            await navigator.clipboard.writeText(pw);
            document.getElementById(ids.status).textContent = i18n.labelPasswordCopied || 'Password copied to clipboard.';
        } catch (e) {
            document.getElementById(ids.error).textContent = i18n.labelFailedCopyPassword || 'Failed to copy password.';
        }
    }

    // ---- Passkeys ----

    const {base64urlToBuffer, bufferToBase64url} = window.WebAuthnUtils;

    async function loadPasskeys() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const card = document.getElementById('passkeyCard');
        const listEl = document.getElementById('passkeyList');
        if (!listEl) return;
        listEl.innerHTML = '';
        try {
            const resp = await fetchJSON(urls.urlListPasskeys);
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedLoadPasskeys || 'Failed to load passkeys.');
            }
            // Server gates the card on sso_allow_passkeys. Keep it hidden
            // entirely when disabled — no listing, no add form.
            if (result.allowed === false) {
                if (card) card.classList.add('is-hidden');
                return;
            }
            if (card) card.classList.remove('is-hidden');
            const passkeys = result.passkeys || [];
            if (passkeys.length === 0) {
                const li = document.createElement('li');
                li.className = 'empty';
                li.textContent = i18n.labelNoPasskeys || 'No passkeys yet.';
                listEl.appendChild(li);
                return;
            }
            for (const p of passkeys) {
                const li = document.createElement('li');
                const label = document.createElement('span');
                label.className = 'device-label';
                label.textContent = p.device_name || p.name;
                li.appendChild(label);
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-secondary btn-small';
                btn.textContent = i18n.labelDeleteBtn || 'Delete';
                btn.addEventListener('click',
                    () => deletePasskey(p.name, p.device_name || p.name));
                li.appendChild(btn);
                listEl.appendChild(li);
            }
        } catch (e) {
            const li = document.createElement('li');
            li.className = 'error-msg';
            li.textContent = e.message || i18n.labelFailedLoadPasskeys || 'Failed to load passkeys.';
            listEl.appendChild(li);
        }
    }

    async function addPasskey() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const statusEl = document.getElementById('passkeyStatus');
        const errorEl = document.getElementById('passkeyError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        if (!window.isSecureContext) {
            errorEl.textContent = i18n.labelHttpsRequired || 'WebAuthn requires HTTPS.';
            return;
        }
        if (!window.PublicKeyCredential) {
            errorEl.textContent = i18n.labelWebauthnUnsupported || 'WebAuthn is not supported in this browser.';
            return;
        }

        const deviceName = document.getElementById('passkeyName').value.trim();
        if (!deviceName) {
            errorEl.textContent = i18n.labelPasskeyNameRequired || 'Passkey name is required.';
            return;
        }

        const btn = document.getElementById('addPasskeyBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelPreparingPasskey || 'Preparing passkey registration...';

        try {
            const beginResp = await fetchJSON(urls.urlPasskeyRegisterBegin, {
                method: 'POST',
                body: JSON.stringify({device_name: deviceName}),
            });
            const beginResult = await beginResp.json();
            if (!beginResp.ok) {
                throw new Error(beginResult.error || i18n.labelFailedStartPasskey || 'Failed to start passkey registration.');
            }

            // python-fido2 serialises challenge/user.id/excludeCredentials[].id
            // as base64url strings — the browser API needs ArrayBuffers.
            const publicKey = beginResult.publicKey;
            publicKey.challenge = base64urlToBuffer(publicKey.challenge);
            publicKey.user.id = base64urlToBuffer(publicKey.user.id);
            if (publicKey.excludeCredentials) {
                publicKey.excludeCredentials = publicKey.excludeCredentials.map(cred => ({
                    ...cred,
                    id: base64urlToBuffer(cred.id),
                }));
            }

            statusEl.textContent = i18n.labelConfirmPasskey || 'Confirm on your device to create the passkey...';
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

            statusEl.textContent = i18n.labelCompletingPasskey || 'Completing registration...';
            const completeResp = await fetchJSON(urls.urlPasskeyRegisterComplete, {
                method: 'POST',
                body: JSON.stringify(regResponse),
            });
            const completeResult = await completeResp.json();
            if (!completeResp.ok) {
                throw new Error(completeResult.error || i18n.labelPasskeyRegFailed || 'Passkey registration failed.');
            }
            statusEl.textContent = i18n.labelPasskeyAdded || 'Passkey added.';
            document.getElementById('passkeyName').value = '';
            loadPasskeys();
        } catch (e) {
            // NotAllowedError covers user cancel + timeout; surface the
            // raw message so users see "this passkey is already
            // registered" etc. unchanged.
            errorEl.textContent = e.message || i18n.labelFailedAddPasskey || 'Failed to add passkey.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    async function deletePasskey(name, label) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const tpl = i18n.labelConfirmDeletePasskey || 'Delete passkey "%(name)s"?';
        if (!confirm(interpolate(tpl, {name: label}))) {
            return;
        }
        const statusEl = document.getElementById('passkeyStatus');
        const errorEl = document.getElementById('passkeyError');
        errorEl.textContent = '';
        try {
            const resp = await fetchJSON(urls.urlDelPasskey, {
                method: 'POST',
                body: JSON.stringify({name: name}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedDeletePasskey || 'Failed to delete passkey.');
            }
            statusEl.textContent = i18n.labelPasskeyDeleted || 'Passkey deleted.';
            loadPasskeys();
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelFailedDeletePasskey || 'Failed to delete passkey.';
        }
    }

    // ---- Admin access (self-service toggle) ----

    async function loadAdminAccess() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const card = document.getElementById('adminAccessCard');
        const toggle = document.getElementById('adminAccessToggle');
        const errorEl = document.getElementById('adminAccessError');
        if (!card || !toggle) return;
        try {
            const resp = await fetchJSON(urls.urlGetAdminAccess);
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelAdminAccessFailedLoad || 'Failed to load admin access state.');
            }
            // available=false → sso_temp_pass_role unresolvable for this
            // user; hide the entire card.
            if (!result.available) {
                card.classList.add('is-hidden');
                return;
            }
            toggle.checked = !!result.enabled;
            card.classList.remove('is-hidden');
        } catch (e) {
            if (errorEl) {
                errorEl.textContent = e.message || i18n.labelAdminAccessFailedLoad || 'Failed to load admin access state.';
            }
        }
    }

    async function onAdminAccessToggle(ev) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const toggle = ev.currentTarget;
        const statusEl = document.getElementById('adminAccessStatus');
        const errorEl = document.getElementById('adminAccessError');
        const desired = toggle.checked;
        statusEl.textContent = '';
        errorEl.textContent = '';
        toggle.disabled = true;
        try {
            const resp = await fetchJSON(urls.urlSetAdminAccess, {
                method: 'POST',
                body: JSON.stringify({enabled: desired}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelAdminAccessFailedSave || 'Failed to update admin access.');
            }
            // Re-sync from server: handles the (rare) case where the
            // server clipped/overrode the request.
            toggle.checked = !!result.enabled;
            statusEl.textContent = result.enabled
                ? (i18n.labelAdminAccessOn || 'Admin access enabled.')
                : (i18n.labelAdminAccessOff || 'Admin access disabled.');
        } catch (e) {
            // Revert UI state on failure so it matches reality.
            toggle.checked = !desired;
            errorEl.textContent = e.message || i18n.labelAdminAccessFailedSave || 'Failed to update admin access.';
        } finally {
            toggle.disabled = false;
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
        const i18n = getPageI18n();
        const listEl = document.getElementById('oidcConsentList');
        if (!urls || !listEl) return;
        listEl.innerHTML = '';
        try {
            const resp = await fetchJSON(urls.urlList);
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedLoadConsents || 'Failed to load consents.');
            }
            const consents = result.consents || [];
            if (consents.length === 0) {
                const li = document.createElement('li');
                li.className = 'empty';
                li.textContent = i18n.labelNoConnectedApps || 'No connected applications.';
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
                    scopes.className = 'hint is-block';
                    scopes.textContent = (i18n.labelScopesPrefix || 'Scopes:') + ' ' + c.scopes.join(', ');
                    label.appendChild(scopes);
                }
                if (c.granted_at) {
                    const granted = document.createElement('span');
                    granted.className = 'hint is-block';
                    granted.textContent = (i18n.labelGrantedPrefix || 'Granted:') + ' ' + formatGrantedAt(c.granted_at);
                    label.appendChild(granted);
                }
                li.appendChild(label);
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-secondary btn-small';
                btn.textContent = i18n.labelDisconnectBtn || 'Disconnect';
                btn.addEventListener('click',
                        () => revokeOidcConsent(c.client_uuid, c.client_name));
                li.appendChild(btn);
                listEl.appendChild(li);
            }
        } catch (e) {
            const li = document.createElement('li');
            li.className = 'error-msg';
            li.textContent = e.message || i18n.labelFailedLoadConsents || 'Failed to load consents.';
            listEl.appendChild(li);
        }
    }

    async function revokeOidcConsent(clientUuid, label) {
        const urls = getConsentUrls();
        if (!urls) return;
        const i18n = getPageI18n();
        const tpl = i18n.labelConfirmRevoke
                || 'Disconnect "%(name)s"? Active sessions for this application will be terminated.';
        if (!confirm(interpolate(tpl, {name: label}))) {
            return;
        }
        const statusEl = document.getElementById('consentStatus');
        const errorEl = document.getElementById('consentError');
        statusEl.textContent = '';
        errorEl.textContent = '';
        try {
            const resp = await fetchJSON(urls.urlRevoke, {
                method: 'POST',
                body: JSON.stringify({client_uuid: clientUuid}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedRevoke || 'Failed to revoke consent.');
            }
            statusEl.textContent = result.message || i18n.labelDisconnected || 'Disconnected.';
            loadOidcConsents();
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelFailedRevoke || 'Failed to revoke consent.';
        }
    }

    async function saveLanguage() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const statusEl = document.getElementById('languageStatus');
        const errorEl = document.getElementById('languageError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const select = document.getElementById('languageSelect');
        const language = select.value;
        const btn = document.getElementById('saveLanguageBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelSaving || 'Saving...';
        try {
            const resp = await fetchJSON(urls.urlChangeLanguage, {
                method: 'POST',
                body: JSON.stringify({language: language}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedSaveLanguage || 'Failed to save language.');
            }
            // Reload so Babel re-renders the page in the new locale.
            window.location.reload();
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelFailedSaveLanguage || 'Failed to save language.';
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

        // Device-token cards (add/copy buttons) are wired up per role
        // inside loadDeviceTokens() / buildRoleCard() since the count
        // and ids depend on the user's configured sso_token_roles.
        loadDeviceTokens();

        const addPasskeyBtn = document.getElementById('addPasskeyBtn');
        if (addPasskeyBtn) addPasskeyBtn.addEventListener('click', addPasskey);
        attachNameSanitizer(document.getElementById('passkeyName'));
        loadPasskeys();

        const adminToggle = document.getElementById('adminAccessToggle');
        if (adminToggle) adminToggle.addEventListener('change', onAdminAccessToggle);
        loadAdminAccess();

        loadOidcConsents();
    });
})();
