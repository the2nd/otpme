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

    // Tell the user the new token cannot sign in just yet, but only
    // when that is true. A token exists the moment we say so; whether
    // it may sign in is decided on the site the account belongs to,
    // and for an account on another site the assignment has to travel
    // there first. ssod sets sync_pending exactly on that path -- for
    // a local account there is nothing to wait for and nothing to say.
    //
    // A dialog rather than a line in the status area: somebody who
    // just registered a key goes off to try it, and a sentence next to
    // the form is easy to walk past. Same native dialogs the rest of
    // this page uses.
    function notifySyncPending(result) {
        if (!result || !result.sync_pending) return;
        const hint = getPageI18n().labelTokenSyncHint;
        if (!hint) return;
        alert(hint);
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

    // What the user typed as the label of a thing they own -- "My
    // Pixel", "work key". It is not the token name: the server derives
    // that from this and keeps the spaces and the capitals in the
    // label. So nothing is rewritten while they type (which is what
    // used to leave "pixel-" and then "pixel " in the field); only the
    // edges are tidied, where a separator is never what anybody meant.
    function cleanNameValue(value) {
        return String(value || '')
            .trim()
            .replace(/-{2,}/g, '-')
            .replace(/^-+|-+$/g, '')
            .trim();
    }

    // One-shot reveal carried across the loadDeviceTokens() call that
    // follows a successful add. The reveal card is part of the per-role
    // card that gets fully rebuilt, so we re-inject the password into
    // the matching card during the next render and then drop the state.
    let pendingReveal = null;

    function deviceTokenTypeLabel(tokenType, i18n) {
        if (tokenType === 'totp') {
            return i18n.labelTypeTotp || 'Authenticator app (TOTP)';
        }
        return i18n.labelTypePassword || 'Password';
    }

    function buildRoleCard(role) {
        // One settings-card per device_token_roles entry. The role description
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
            startBtn    : `startDeviceBtn_${safeUuid}`,
            fields      : `deviceAddFields_${safeUuid}`,
            // This card's entry in ADD_FORMS.
            formKey     : `device:${safeUuid}`,
            limit       : `deviceLimit_${safeUuid}`,
            typeField   : `deviceTypeField_${safeUuid}`,
            typeSelect  : `deviceType_${safeUuid}`,
            pwBlock     : `devicePwBlock_${safeUuid}`,
            totpBlock   : `deviceTotpBlock_${safeUuid}`,
            qrImg       : `deviceQr_${safeUuid}`,
            secret      : `deviceSecret_${safeUuid}`,
        };
        const card = document.createElement('div');
        card.className = 'settings-card';
        card.dataset.roleUuid = role.role_uuid;
        const heading = `${i18n.labelDeviceTokens || 'Device Tokens'} — ${role.role_name || ''}`;
        card.innerHTML = `
            <h3></h3>
            <p class="settings-desc"></p>
            <div class="settings-form">
                <button type="button" id="${ids.startBtn}" class="btn btn-primary"></button>
                <div id="${ids.limit}" class="hint is-hidden"></div>
                <div id="${ids.fields}" class="is-hidden">
                    <div id="${ids.typeField}" class="is-hidden">
                        <label for="${ids.typeSelect}"></label>
                        <select id="${ids.typeSelect}"></select>
                    </div>
                    <label for="${ids.nameInput}"></label>
                    <input type="text" id="${ids.nameInput}" autocomplete="off">
                    <button type="button" id="${ids.addBtn}" class="btn btn-primary mt-8"></button>
                </div>
                <div class="status-msg" id="${ids.status}"></div>
                <div class="error-msg" id="${ids.error}"></div>
            </div>
            <div id="${ids.result}" class="device-token-reveal is-hidden">
                <div id="${ids.pwBlock}">
                    <strong></strong>
                    <code id="${ids.password}"></code>
                    <button type="button" id="${ids.copyBtn}" class="btn btn-secondary btn-small ml-8"></button>
                </div>
                <div id="${ids.totpBlock}" class="is-hidden">
                    <p class="totp-scan"></p>
                    <div class="qr-container"><img id="${ids.qrImg}" alt=""></div>
                    <div><strong class="totp-secret-label"></strong> <code id="${ids.secret}"></code></div>
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
        card.querySelector(`#${ids.startBtn}`).textContent = i18n.labelAddDeviceToken || 'Add Device Token';
        card.querySelector(`#${ids.result} strong`).textContent = i18n.labelNewPassword || 'New password:';
        card.querySelector(`#${ids.copyBtn}`).textContent = i18n.labelCopy || 'Copy';
        card.querySelector(`#${ids.result} span.hint`).textContent = i18n.labelShownOnce || '';
        card.querySelector('h4').textContent = i18n.labelExistingDeviceTokens || 'Existing Device Tokens';
        card.querySelector(`#${ids.totpBlock} .totp-scan`).textContent =
                i18n.labelScanTotp || 'Scan this code with your authenticator app:';
        card.querySelector(`#${ids.totpBlock} .totp-secret-label`).textContent =
                i18n.labelTotpSecret || 'Secret:';
        card.querySelector(`#${ids.qrImg}`).alt = i18n.labelTotpQrAlt || 'TOTP code';
        // What the role lets this user create (device_token_types). A
        // choice only where there is one: with a single type ssod takes
        // it without being told.
        const tokenTypes = role.token_types || ['password'];
        if (tokenTypes.length > 1) {
            const select = card.querySelector(`#${ids.typeSelect}`);
            for (const tokenType of tokenTypes) {
                const opt = document.createElement('option');
                opt.value = tokenType;
                opt.textContent = deviceTokenTypeLabel(tokenType, i18n);
                select.appendChild(opt);
            }
            card.querySelector(`label[for="${ids.typeSelect}"]`).textContent =
                    i18n.labelDeviceTokenType || 'Token Type';
            card.querySelector(`#${ids.typeField}`).classList.remove('is-hidden');
        }
        // max_device_tokens: once the user has as many as the role
        // allows, there is no form to open. ssod refuses the add either
        // way; this only saves them typing a name for nothing.
        const maxTokens = role.max_device_tokens;
        if (maxTokens && (role.device_tokens || []).length >= maxTokens) {
            card.querySelector(`#${ids.startBtn}`).classList.add('is-hidden');
            const limitEl = card.querySelector(`#${ids.limit}`);
            limitEl.textContent = interpolate(i18n.labelMaxDeviceTokens
                    || 'You have the maximum number of device tokens for this role ({max}).',
                    {max: maxTokens});
            limitEl.classList.remove('is-hidden');
        }

        card.querySelector(`#${ids.addBtn}`).addEventListener('click',
            () => addDeviceToken(role.role_uuid, ids));
        // Rebuilt on every reload of the list, which also puts the form
        // back to closed after a token was added.
        ADD_FORMS[ids.formKey] = {start: ids.startBtn, fields: ids.fields,
                                input: ids.nameInput, hash: `#${ids.startBtn}`,
                                flow: 'device'};
        card.querySelector(`#${ids.startBtn}`).addEventListener('click',
            () => onStartAdd(ids.formKey));
        card.querySelector(`#${ids.copyBtn}`).addEventListener('click',
            () => copyDevicePassword(ids));

        // Restore the one-shot reveal from the add that triggered this
        // render. Consumed so a subsequent unrelated reload (e.g. a
        // delete on another card) does not resurrect the password.
        if (pendingReveal && pendingReveal.role_uuid === role.role_uuid) {
            const resultEl = card.querySelector(`#${ids.result}`);
            if (pendingReveal.token_type === 'totp') {
                card.querySelector(`#${ids.pwBlock}`).classList.add('is-hidden');
                card.querySelector(`#${ids.totpBlock}`).classList.remove('is-hidden');
                card.querySelector(`#${ids.qrImg}`).src = pendingReveal.qrcode_img || '';
                card.querySelector(`#${ids.secret}`).textContent = pendingReveal.secret || '';
                card.querySelector(`#${ids.result} span.hint`).textContent =
                        i18n.labelTotpShownOnce || 'This code is shown only once. Scan it now.';
            } else {
                card.querySelector(`#${ids.password}`).textContent = pendingReveal.password;
            }
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
                // A password token is what a device token always was;
                // only the other kind says what it is.
                if (t.token_type === 'totp') {
                    const badge = document.createElement('span');
                    badge.className = 'device-badge';
                    badge.textContent = i18n.labelTypeTotpShort || 'TOTP';
                    label.appendChild(document.createTextNode(' '));
                    label.appendChild(badge);
                }
                li.appendChild(label);
                const actions = document.createElement('span');
                actions.className = 'device-token-actions';
                actions.appendChild(buildEnableToggle({
                    enabled: !!t.enabled,
                    onChange: (desired) => toggleDeviceToken(t.name, desired),
                    fallbackError: getPageI18n().labelFailedToggleDeviceToken || 'Failed to update device token.',
                }));
                const delBtn = document.createElement('button');
                delBtn.type = 'button';
                delBtn.className = 'btn btn-secondary btn-small';
                delBtn.textContent = i18n.labelDelete || 'Delete';
                delBtn.addEventListener('click',
                    () => deleteDeviceToken(t.name, t.device_name || t.name));
                actions.appendChild(delBtn);
                li.appendChild(actions);
                listEl.appendChild(li);
            }
        }
        return card;
    }

    async function loadDeviceTokens() {
        const urls = getUrls();
        const pageI18n = getPageI18n();
        const container = document.getElementById('deviceRolesContainer');
        container.innerHTML = '';
        try {
            const resp = await fetchJSON(urls.urlListDeviceTokens);
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || pageI18n.labelFailedLoadDeviceTokens || 'Failed to load device tokens.');
            }
            const rolesConfigured = !!result.roles_configured;
            const roles = result.roles || [];
            // device_token_roles not configured (or empty) -> render
            // nothing. The whole device-tokens section disappears from
            // the settings page rather than showing an explanatory hint.
            if (!rolesConfigured || roles.length === 0) {
                return;
            }
            for (const role of roles) {
                container.appendChild(buildRoleCard(role));
            }
        } catch (e) {
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

        const deviceName = cleanNameValue(document.getElementById(ids.nameInput).value);
        if (!deviceName) {
            errorEl.textContent = i18n.labelDeviceNameRequired || 'Device name is required.';
            return;
        }

        // Only there when the role offers more than one type; without it
        // ssod takes the role's only one.
        const typeSelect = document.getElementById(ids.typeSelect);
        const tokenType = (typeSelect && typeSelect.options.length)
                ? typeSelect.value : '';

        const btn = document.getElementById(ids.addBtn);
        btn.disabled = true;
        statusEl.textContent = i18n.labelAddingDeviceToken || 'Adding device token...';

        try {
            const resp = await fetchJSON(urls.urlAddDeviceToken, {
                method: 'POST',
                body: JSON.stringify({device_name: deviceName, role_uuid: roleUuid,
                                    token_type: tokenType}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                // Back to this role's card, which is where the button
                // the user just pressed will be waiting for them.
                if (handleStepUp(result, `#${ids.startBtn}`,
                        {flow: ids.formKey,
                        input: ids.nameInput, button: ids.addBtn,
                        status: ids.status, value: deviceName, auto: true,
                        select: ids.typeSelect, selectValue: tokenType})) {
                    return;
                }
                throw new Error(result.error || i18n.labelFailedAddDeviceToken || 'Failed to add device token.');
            }
            // Stash the password for the next render to pick up — the
            // current card (incl. resultEl/passwordEl/statusEl) is about
            // to be destroyed and rebuilt by loadDeviceTokens().
            pendingReveal = {
                    role_uuid:  roleUuid,
                    token_type: result.token_type || 'password',
                    password:   result.password || '',
                    secret:     result.secret || '',
                    qrcode_img: result.qrcode_img || '',
                };
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
        const tpl = i18n.labelConfirmDeleteDeviceToken || 'Delete device token "{name}"?';
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
            preserveScrollAround(loadDeviceTokens);
        } catch (e) {
            // Reload anyway so any reveal panel is dropped; the next render
            // will surface the error context implicitly via stale state.
            preserveScrollAround(loadDeviceTokens);
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
                const actions = document.createElement('span');
                actions.className = 'device-token-actions';
                actions.appendChild(buildEnableToggle({
                    enabled: !!p.enabled,
                    onChange: (desired) => togglePasskey(p.name, desired),
                    fallbackError: i18n.labelFailedTogglePasskey || 'Failed to update passkey.',
                    lockedReason: p.is_current ? noDisableReason() : null,
                }));
                const btn = document.createElement('button');
                btn.type = 'button';
                btn.className = 'btn btn-secondary btn-small';
                btn.textContent = i18n.labelDeleteBtn || 'Delete';
                if (p.is_current) {
                    actions.appendChild(lockControl(btn, noDeleteReason()));
                } else {
                    btn.addEventListener('click',
                        () => deletePasskey(p.name, p.device_name || p.name));
                    actions.appendChild(btn);
                }
                li.appendChild(actions);
                listEl.appendChild(li);
            }
        } catch (e) {
            const li = document.createElement('li');
            li.className = 'error-msg';
            li.textContent = e.message || i18n.labelFailedLoadPasskeys || 'Failed to load passkeys.';
            listEl.appendChild(li);
        }
    }

    // Thrown once the browser is on its way to /reauth. There is
    // nothing to report then -- the page is going away.
    const STEP_UP_REDIRECT = 'step-up-redirect';

    // What the user was about to add when the server wanted a fresh
    // step-up first. Kept across the trip to /reauth so that coming
    // back finishes the job instead of leaving them on an empty form
    // with nothing created -- see resumePendingAdd().
    //
    // sessionStorage: per tab, gone with it, and nothing in here is a
    // secret -- a device name, and which button it belongs to.
    const PENDING_ADD_KEY = 'otpme-settings-pending-add';
    // A reauth takes a scan or a key touch, not an afternoon. Anything
    // older is somebody coming back to the page for another reason.
    const PENDING_ADD_MAX_AGE_MS = 5 * 60 * 1000;

    // A write the server refused for want of a fresh step-up
    // (deploy_*_reauth). Sends the user to /reauth and back to the card
    // they were on, and remembers <pending> so the add is picked up
    // again there.
    //
    // Returns true when it took over, so callers can stop right there.
    function handleStepUp(body, hash, pending) {
        if (!body || !body.step_up_required) return false;
        if (pending) {
            try {
                sessionStorage.setItem(PENDING_ADD_KEY, JSON.stringify(
                        Object.assign({hash: hash, at: Date.now()}, pending)));
            } catch (e) { /* sessionStorage disabled: press again */ }
        }
        _driveReauth(hash);
        return true;
    }

    // Back from /reauth: put the name back and carry on.
    //
    // Pressed for the user where that is possible -- a device token and
    // a phone need nothing but a request. Not for a security key or a
    // passkey: the browser only lets a page register one in answer to
    // a real click (Safari insists, others may follow), and a click we
    // fake would fail there with an error that explains nothing. Those
    // get the name back and a word to press again.
    //
    // Only when we landed on the card the trip started from, which is
    // what says the reauth actually happened rather than the user
    // wandering off and coming back later.
    function resumePendingAdd() {
        let pending = null;
        try {
            pending = JSON.parse(sessionStorage.getItem(PENDING_ADD_KEY));
            sessionStorage.removeItem(PENDING_ADD_KEY);
        } catch (e) {
            return;
        }
        if (!pending || !pending.hash) return;
        if (window.location.hash !== pending.hash) return;
        if (Date.now() - (pending.at || 0) > PENDING_ADD_MAX_AGE_MS) return;
        // It has done its job. Leaving it would make a reload look like
        // another trip back from /reauth.
        history.replaceState(null, '', window.location.pathname
                                        + window.location.search);
        // Sent away by a start button (see onStartAdd()): the
        // reauth is done, so the form it was holding back opens, and
        // the user's next click -- the one after typing the name -- is
        // the one that registers.
        if (pending.open) {
            if (ADD_FORMS[pending.open]) openAddFields(pending.open);
            return;
        }
        // The fallback of a window that ran out between opening the
        // form and pressing its button: the form is closed on every
        // page load, and the name has to go back into it.
        if (pending.flow) showAddFields(pending.flow, true);
        const input = document.getElementById(pending.input);
        const button = document.getElementById(pending.button);
        if (!input || !button) return;
        input.value = pending.value || '';
        // The token type a device token card had picked, which the
        // page load put back to the role's first.
        if (pending.select && pending.selectValue) {
            const select = document.getElementById(pending.select);
            if (select) select.value = pending.selectValue;
        }
        if (pending.auto) {
            button.click();
            return;
        }
        const statusEl = document.getElementById(pending.status);
        if (statusEl) {
            statusEl.textContent = getPageI18n().labelStepUpPressAgain
                    || 'Confirmed. Press the button again to continue.';
        }
        button.focus();
    }

    // The add forms of the cards. Closed until the user asks for one,
    // and opened only once the reauth is out of the way -- so the user
    // proves themselves first and then types a name, rather than typing
    // it, being sent away, and finding it gone. For a security key or a
    // passkey there is no other way at all: the browser registers one
    // only in answer to a real click, and /reauth reloads the page.
    //
    // <flow> is the key get_step_up_state answers under. The device
    // token cards are built per role and add themselves here, see
    // buildRoleCard().
    const ADD_FORMS = {
        passkey: {start: 'startPasskeyBtn', fields: 'passkeyAddFields',
                input: 'passkeyName', hash: '#passkeyCard', flow: 'passkey'},
        fido2:   {start: 'startFido2Btn', fields: 'fido2AddFields',
                input: 'fido2DeviceName', hash: '#fido2Card', flow: 'fido2'},
        tiqr:    {start: 'startTiqrBtn', fields: 'tiqrAddFields',
                input: 'tiqrDeviceName', hash: '#tiqrCard', flow: 'tiqr'},
    };

    function showAddFields(flow, open) {
        const form = ADD_FORMS[flow];
        if (!form) return;
        const start = document.getElementById(form.start);
        const fields = document.getElementById(form.fields);
        if (start) start.classList.toggle('is-hidden', open);
        if (fields) fields.classList.toggle('is-hidden', !open);
    }

    function openAddFields(flow) {
        showAddFields(flow, true);
        const input = document.getElementById(ADD_FORMS[flow].input);
        if (input) input.focus();
    }

    // The add button of a card. Asks at the moment it is
    // pressed rather than on page load, so the answer is as fresh as
    // it can be: through /reauth first when one is due, straight to the
    // form when not.
    //
    // A failed question opens the form anyway. The add command asks
    // for the reauth itself, so nothing gets past it -- the user just
    // gets the press-again fallback instead of this.
    async function onStartAdd(flow) {
        const urls = getUrls();
        const form = ADD_FORMS[flow];
        let missing = false;
        try {
            const resp = await fetchJSON(urls.urlStepUpState);
            const body = await resp.json();
            if (resp.ok) missing = !!(body.step_up_missing || {})[form.flow];
        } catch (e) {
            missing = false;
        }
        if (!missing) {
            openAddFields(flow);
            return;
        }
        try {
            sessionStorage.setItem(PENDING_ADD_KEY, JSON.stringify(
                    {hash: form.hash, at: Date.now(), open: flow}));
        } catch (e) { /* sessionStorage disabled: press the button again */ }
        _driveReauth(form.hash);
    }

    // The WebAuthn registration dance. Identical for a passkey and for
    // a security key -- ask the server for create-options, let the
    // browser talk to the authenticator, post back what it signed. The
    // two differ in where they post and what they call the thing, which
    // is what the arguments are for. Throws; the caller reports.
    async function registerWebAuthnCredential(opts) {
        const beginResp = await fetchJSON(opts.beginUrl, {
            method: 'POST',
            body: JSON.stringify({device_name: opts.deviceName}),
        });
        const beginResult = await beginResp.json();
        if (!beginResp.ok) {
            if (handleStepUp(beginResult, opts.stepUpHash, opts.stepUpPending)) {
                throw new Error(STEP_UP_REDIRECT);
            }
            throw new Error(beginResult.error || opts.beginFailed);
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

        opts.statusEl.textContent = opts.confirmLabel;
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

        opts.statusEl.textContent = opts.completingLabel;
        const completeResp = await fetchJSON(opts.completeUrl, {
            method: 'POST',
            body: JSON.stringify(regResponse),
        });
        const completeResult = await completeResp.json();
        if (!completeResp.ok) {
            throw new Error(completeResult.error || opts.completeFailed);
        }
        return completeResult;
    }

    // What both add-buttons check before touching the WebAuthn API.
    // Returns an error message, or null when it is safe to go ahead.
    function webAuthnUnavailable() {
        const i18n = getPageI18n();
        if (!window.isSecureContext) {
            return i18n.labelHttpsRequired || 'WebAuthn requires HTTPS.';
        }
        if (!window.PublicKeyCredential) {
            return i18n.labelWebauthnUnsupported
                    || 'WebAuthn is not supported in this browser.';
        }
        return null;
    }

    async function addPasskey() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const statusEl = document.getElementById('passkeyStatus');
        const errorEl = document.getElementById('passkeyError');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const unavailable = webAuthnUnavailable();
        if (unavailable) {
            errorEl.textContent = unavailable;
            return;
        }

        const deviceName = cleanNameValue(document.getElementById('passkeyName').value);
        if (!deviceName) {
            errorEl.textContent = i18n.labelPasskeyNameRequired || 'Passkey name is required.';
            return;
        }

        const btn = document.getElementById('addPasskeyBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelPreparingPasskey || 'Preparing passkey registration...';

        try {
            const result = await registerWebAuthnCredential({
                beginUrl:        urls.urlPasskeyRegisterBegin,
                completeUrl:     urls.urlPasskeyRegisterComplete,
                deviceName:      deviceName,
                statusEl:        statusEl,
                confirmLabel:    i18n.labelConfirmPasskey
                                || 'Confirm on your device to create the passkey...',
                completingLabel: i18n.labelCompletingPasskey || 'Completing registration...',
                beginFailed:     i18n.labelFailedStartPasskey
                                || 'Failed to start passkey registration.',
                completeFailed:  i18n.labelPasskeyRegFailed || 'Passkey registration failed.',
                stepUpHash:      '#passkeyCard',
                stepUpPending:   {flow: 'passkey',
                                input: 'passkeyName', button: 'addPasskeyBtn',
                                status: 'passkeyStatus', value: deviceName,
                                auto: false},
            });
            statusEl.textContent = i18n.labelPasskeyAdded || 'Passkey added.';
            document.getElementById('passkeyName').value = '';
            // Back to the button: the next one asks again.
            showAddFields('passkey', false);
            loadPasskeys();
            notifySyncPending(result);
        } catch (e) {
            if (e.message === STEP_UP_REDIRECT) return;
            // NotAllowedError covers user cancel + timeout; surface the
            // raw message so users see "this passkey is already
            // registered" etc. unchanged.
            errorEl.textContent = e.message || i18n.labelFailedAddPasskey || 'Failed to add passkey.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    // ---- FIDO2 security keys ----

    async function addFido2Token() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const statusEl = document.getElementById('fido2Status');
        const errorEl = document.getElementById('fido2Error');
        statusEl.textContent = '';
        errorEl.textContent = '';

        const unavailable = webAuthnUnavailable();
        if (unavailable) {
            errorEl.textContent = unavailable;
            return;
        }

        const deviceName = cleanNameValue(document.getElementById('fido2DeviceName').value);
        if (!deviceName) {
            errorEl.textContent = i18n.labelKeyNameRequired || 'Key name is required.';
            return;
        }

        const btn = document.getElementById('addFido2Btn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelAddingFido2 || 'Registering security key...';

        try {
            const result = await registerWebAuthnCredential({
                beginUrl:        urls.urlFido2AddBegin,
                completeUrl:     urls.urlFido2AddComplete,
                deviceName:      deviceName,
                statusEl:        statusEl,
                confirmLabel:    i18n.labelTouchKey || 'Touch your security key...',
                completingLabel: i18n.labelCompletingPasskey || 'Completing registration...',
                beginFailed:     i18n.labelFailedAddFido2
                                || 'Failed to register security key.',
                completeFailed:  i18n.labelFailedAddFido2
                                || 'Failed to register security key.',
                stepUpHash:      '#fido2Card',
                stepUpPending:   {flow: 'fido2',
                                input: 'fido2DeviceName', button: 'addFido2Btn',
                                status: 'fido2Status', value: deviceName,
                                auto: false},
            });
            statusEl.textContent = i18n.labelFido2Added || 'Security key registered.';
            document.getElementById('fido2DeviceName').value = '';
            // Back to the button: the next one asks again.
            showAddFields('fido2', false);
            loadFido2Tokens();
            notifySyncPending(result);
        } catch (e) {
            if (e.message === STEP_UP_REDIRECT) return;
            errorEl.textContent = e.message || i18n.labelFailedAddFido2
                    || 'Failed to register security key.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    async function deleteFido2Token(name, label) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const tpl = i18n.labelConfirmDeleteFido2 || 'Delete security key "{name}"?';
        if (!confirm(interpolate(tpl, {name: label}))) {
            return;
        }
        const errorEl = document.getElementById('fido2Error');
        errorEl.textContent = '';
        try {
            const resp = await fetchJSON(urls.urlDelFido2, {
                method: 'POST',
                body: JSON.stringify({name: name}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedDeleteFido2
                        || 'Failed to delete security key.');
            }
            preserveScrollAround(loadFido2Tokens);
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelFailedDeleteFido2
                    || 'Failed to delete security key.';
        }
    }

    async function toggleFido2Token(name, desired) {
        const urls = getUrls();
        const resp = await fetchJSON(urls.urlToggleFido2, {
            method: 'POST',
            body: JSON.stringify({name: name, enabled: desired}),
        });
        const result = await resp.json();
        if (!resp.ok) {
            throw new Error(result.error || getPageI18n().labelFailedToggleFido2
                    || 'Failed to update security key.');
        }
        return result.enabled;
    }

    async function loadFido2Tokens() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const card = document.getElementById('fido2Card');
        const listEl = document.getElementById('fido2List');
        if (!card || !listEl) return;
        listEl.innerHTML = '';
        try {
            const resp = await fetchJSON(urls.urlListFido2);
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedLoadFido2
                        || 'Failed to load security keys.');
            }
            // allowed=false means sso_allow_fido2 is off for this user;
            // the whole card stays hidden, as the passkey card does.
            if (!result.allowed) {
                card.classList.add('is-hidden');
                return;
            }
            card.classList.remove('is-hidden');
            const tokens = result.fido2_tokens || [];
            const ssoToken = result.sso_token || {};
            if (tokens.length === 0) {
                const li = document.createElement('li');
                li.className = 'empty';
                li.textContent = i18n.labelNoFido2 || 'No security keys registered yet.';
                listEl.appendChild(li);
                return;
            }
            for (const t of tokens) {
                const li = document.createElement('li');
                const label = document.createElement('span');
                label.className = 'device-label';
                label.textContent = t.device_name || t.name;
                if (t.is_sso_token) {
                    const badge = document.createElement('span');
                    badge.className = 'device-badge';
                    badge.textContent = i18n.labelSsoToken || 'Default token';
                    label.appendChild(document.createTextNode(' '));
                    label.appendChild(badge);
                }
                li.appendChild(label);
                const actions = document.createElement('span');
                actions.className = 'device-token-actions';
                // The SSO token stays enabled and stays put, same as in
                // the tiqr list. Everything else can be switched off,
                // removed, or promoted.
                if (!t.is_sso_token) {
                    actions.appendChild(buildEnableToggle({
                        enabled: !!t.enabled,
                        onChange: (desired) => toggleFido2Token(t.name, desired),
                        fallbackError: i18n.labelFailedToggleFido2
                                || 'Failed to update security key.',
                        lockedReason: t.is_current ? noDisableReason() : null,
                    }));
                    const promoteBtn = document.createElement('button');
                    promoteBtn.type = 'button';
                    promoteBtn.className = 'btn btn-secondary btn-small';
                    promoteBtn.textContent = i18n.labelMakeSsoToken || 'Make default token';
                    promoteBtn.addEventListener('click',
                        () => promoteToken(t.name, t.device_name || t.name,
                                        ssoToken,
                                        {statusId: 'fido2Status',
                                        errorId: 'fido2Error'}));
                    actions.appendChild(promoteBtn);
                    const delBtn = document.createElement('button');
                    delBtn.type = 'button';
                    delBtn.className = 'btn btn-secondary btn-small';
                    delBtn.textContent = i18n.labelDeleteBtn || 'Delete';
                    if (t.is_current) {
                        actions.appendChild(lockControl(delBtn, noDeleteReason()));
                    } else {
                        delBtn.addEventListener('click',
                            () => deleteFido2Token(t.name, t.device_name || t.name));
                        actions.appendChild(delBtn);
                    }
                }
                li.appendChild(actions);
                listEl.appendChild(li);
            }
        } catch (e) {
            const li = document.createElement('li');
            li.className = 'error-msg';
            li.textContent = e.message || i18n.labelFailedLoadFido2
                    || 'Failed to load security keys.';
            listEl.appendChild(li);
        }
    }

    // Build a small enable/disable toggle switch used next to the
     // delete button on each device-token / passkey row. The visual
     // markup matches the toggle-switch used by the admin-access card
     // (see settings.html) so the styles from base.css apply.
    function noDeleteReason() {
        const i18n = getPageI18n();
        return i18n.labelCurrentTokenNoDelete
                || 'You are signed in with this one. Sign in with another '
                    + 'factor to remove it.';
    }

    function noDisableReason() {
        const i18n = getPageI18n();
        return i18n.labelCurrentTokenNoDisable
                || 'You are signed in with this one. Sign in with another '
                    + 'factor to switch it off.';
    }

    // Turn a control off with a reason the user can read. The server
    // refuses these anyway; showing why beats letting somebody press
    // the button and get an error back.
    //
    // The reason goes on a wrapper, not on the control: a disabled
    // element fires no pointer events, so a title sitting on it would
    // never show a tooltip. Returns the wrapper -- append that.
    function lockControl(el, reason) {
        el.disabled = true;
        el.setAttribute('aria-label', reason);
        const holder = document.createElement('span');
        holder.className = 'locked-control';
        holder.title = reason;
        holder.appendChild(el);
        return holder;
    }

    function buildEnableToggle({enabled, onChange, fallbackError, lockedReason}) {
        const i18n = getPageI18n();
        const wrapper = document.createElement('label');
        wrapper.className = 'toggle-switch';
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.setAttribute('role', 'switch');
        input.checked = !!enabled;
        input.title = enabled
            ? (i18n.labelTokenEnabled || 'Enabled')
            : (i18n.labelTokenDisabled || 'Disabled');
        input.setAttribute('aria-label', input.title);
        if (lockedReason) {
            // The label around it is not disabled, so it can carry the
            // tooltip -- no extra wrapper needed here.
            input.disabled = true;
            input.setAttribute('aria-label', lockedReason);
            wrapper.title = lockedReason;
        }
        const track = document.createElement('span');
        track.className = 'toggle-track';
        track.setAttribute('aria-hidden', 'true');
        wrapper.appendChild(input);
        wrapper.appendChild(track);
        input.addEventListener('change', async () => {
            const desired = input.checked;
            input.disabled = true;
            try {
                const newEnabled = await onChange(desired);
                input.checked = !!newEnabled;
                input.title = newEnabled
                    ? (i18n.labelTokenEnabled || 'Enabled')
                    : (i18n.labelTokenDisabled || 'Disabled');
                input.setAttribute('aria-label', input.title);
            } catch (e) {
                // Revert UI state on failure so it matches reality.
                input.checked = !desired;
                alert(e.message || fallbackError || 'Update failed.');
            } finally {
                input.disabled = false;
            }
        });
        return wrapper;
    }

    async function toggleDeviceToken(name, enabled) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const resp = await fetchJSON(urls.urlToggleDeviceToken, {
            method: 'POST',
            body: JSON.stringify({name: name, enabled: enabled}),
        });
        const result = await resp.json();
        if (!resp.ok) {
            throw new Error(result.error || i18n.labelFailedToggleDeviceToken || 'Failed to update device token.');
        }
        return !!result.enabled;
    }

    async function togglePasskey(name, enabled) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const resp = await fetchJSON(urls.urlTogglePasskey, {
            method: 'POST',
            body: JSON.stringify({name: name, enabled: enabled}),
        });
        const result = await resp.json();
        if (!resp.ok) {
            throw new Error(result.error || i18n.labelFailedTogglePasskey || 'Failed to update passkey.');
        }
        return !!result.enabled;
    }

    async function deletePasskey(name, label) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const tpl = i18n.labelConfirmDeletePasskey || 'Delete passkey "{name}"?';
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
            preserveScrollAround(loadPasskeys);
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelFailedDeletePasskey || 'Failed to delete passkey.';
        }
    }

    // ---- tiqr ----
    //
    // The list shows every enrolled phone, the SSO token among them.
    // That one is marked and has no delete button: removing it would
    // take the recovery flow with it, which looks up a token of that
    // name. Moving the role to another phone is the "Make SSO token"
    // button, which renames instead of deleting so no phone is lost.

    let tiqrPollTimer = null;

    function stopTiqrPolling() {
        if (tiqrPollTimer === null) return;
        clearTimeout(tiqrPollTimer);
        tiqrPollTimer = null;
    }

    async function loadTiqrTokens() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const card = document.getElementById('tiqrCard');
        const listEl = document.getElementById('tiqrList');
        if (!listEl) return;
        listEl.innerHTML = '';
        try {
            const resp = await fetchJSON(urls.urlListTiqr);
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedLoadTiqr || 'Failed to load phones.');
            }
            // allowed=false means sso_allow_tiqr is off for this user;
            // hide the whole card, as the other two do.
            if (card && !result.allowed) {
                card.classList.add('is-hidden');
                return;
            }
            if (card) card.classList.remove('is-hidden');
            const tokens = result.tiqr_tokens || [];
            // Whatever holds the SSO role right now. Promoting renames
            // it, and it need not be one of the phones below -- it can
            // just as well be a security key.
            const ssoToken = result.sso_token || {};
            if (tokens.length === 0) {
                const li = document.createElement('li');
                li.className = 'empty';
                li.textContent = i18n.labelNoTiqr || 'No phones enrolled yet.';
                listEl.appendChild(li);
                return;
            }
            for (const t of tokens) {
                const li = document.createElement('li');
                const label = document.createElement('span');
                label.className = 'device-label';
                label.textContent = t.device_name || t.name;
                if (t.is_sso_token) {
                    const badge = document.createElement('span');
                    badge.className = 'device-badge';
                    badge.textContent = i18n.labelSsoToken || 'Default token';
                    label.appendChild(document.createTextNode(' '));
                    label.appendChild(badge);
                }
                li.appendChild(label);
                const actions = document.createElement('span');
                actions.className = 'device-token-actions';
                // The SSO token stays enabled and stays put. Everything
                // else can be switched off, removed, or promoted.
                if (!t.is_sso_token) {
                    actions.appendChild(buildEnableToggle({
                        enabled: !!t.enabled,
                        onChange: (desired) => toggleTiqrToken(t.name, desired),
                        fallbackError: i18n.labelFailedToggleTiqr || 'Failed to update phone.',
                        lockedReason: t.is_current ? noDisableReason() : null,
                    }));
                    const promoteBtn = document.createElement('button');
                    promoteBtn.type = 'button';
                    promoteBtn.className = 'btn btn-secondary btn-small';
                    promoteBtn.textContent = i18n.labelMakeSsoToken || 'Make default token';
                    promoteBtn.addEventListener('click',
                        () => promoteToken(t.name, t.device_name || t.name,
                                        ssoToken,
                                        {statusId: 'tiqrStatus',
                                        errorId: 'tiqrError'}));
                    actions.appendChild(promoteBtn);
                    const delBtn = document.createElement('button');
                    delBtn.type = 'button';
                    delBtn.className = 'btn btn-secondary btn-small';
                    delBtn.textContent = i18n.labelDeleteBtn || 'Delete';
                    if (t.is_current) {
                        actions.appendChild(lockControl(delBtn, noDeleteReason()));
                    } else {
                        delBtn.addEventListener('click',
                            () => deleteTiqrToken(t.name, t.device_name || t.name));
                        actions.appendChild(delBtn);
                    }
                }
                li.appendChild(actions);
                listEl.appendChild(li);
            }
        } catch (e) {
            const li = document.createElement('li');
            li.className = 'error-msg';
            li.textContent = e.message || i18n.labelFailedLoadTiqr || 'Failed to load phones.';
            listEl.appendChild(li);
        }
    }

    function showTiqrEnrollBox(show) {
        const box = document.getElementById('tiqrEnrollBox');
        const form = document.getElementById('tiqrAddForm');
        if (box) box.classList.toggle('is-hidden', !show);
        if (form) form.classList.toggle('is-hidden', show);
        // The box goes away when the phone enrolled, the code expired
        // or the user cancelled -- in every case the form goes back to
        // its button, and the next phone asks again.
        if (!show) showAddFields('tiqr', false);
    }

    async function addTiqrToken() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const statusEl = document.getElementById('tiqrStatus');
        const errorEl = document.getElementById('tiqrError');
        errorEl.textContent = '';
        const deviceName = cleanNameValue(document.getElementById('tiqrDeviceName').value);
        if (!deviceName) {
            errorEl.textContent = i18n.labelTiqrNameRequired || 'Device name is required.';
            return;
        }
        const btn = document.getElementById('addTiqrBtn');
        btn.disabled = true;
        statusEl.textContent = i18n.labelPreparingTiqr || 'Preparing enrollment...';
        try {
            const resp = await fetchJSON(urls.urlTiqrEnrollBegin, {
                method: 'POST',
                body: JSON.stringify({device_name: deviceName}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                if (handleStepUp(result, '#tiqrCard',
                        {flow: 'tiqr',
                        input: 'tiqrDeviceName', button: 'addTiqrBtn',
                        status: 'tiqrStatus', value: deviceName, auto: true})) {
                    return;
                }
                throw new Error(result.error || i18n.labelFailedStartTiqr || 'Failed to start tiqr enrollment.');
            }
            const img = document.getElementById('tiqrQrcodeImg');
            if (img) img.src = result.qrcode_img || '';
            // The code only. enroll_url is deliberately not put into a
            // link -- see the comment in settings.html.
            showTiqrEnrollBox(true);
            statusEl.textContent = i18n.labelWaitingTiqr || 'Waiting for your phone...';
            pollTiqrEnrollment();
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelFailedStartTiqr || 'Failed to start tiqr enrollment.';
            statusEl.textContent = '';
        } finally {
            btn.disabled = false;
        }
    }

    function pollTiqrEnrollment() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const statusEl = document.getElementById('tiqrStatus');
        const errorEl = document.getElementById('tiqrError');
        // The grant expires after tiqr_enrollment_expiry (five minutes
        // by default). Give up a little after that rather than polling
        // forever on a page somebody left open.
        const deadline = Date.now() + 330000;
        stopTiqrPolling();

        async function tick() {
            if (Date.now() > deadline) {
                stopTiqrPolling();
                showTiqrEnrollBox(false);
                statusEl.textContent = '';
                errorEl.textContent = i18n.labelTiqrTimeout || 'The code expired. Please try again.';
                return;
            }
            try {
                const resp = await fetchJSON(urls.urlTiqrEnrollStatus);
                const result = await resp.json();
                if (resp.ok && result.status === 'ok') {
                    stopTiqrPolling();
                    showTiqrEnrollBox(false);
                    document.getElementById('tiqrDeviceName').value = '';
                    statusEl.textContent = i18n.labelTiqrAdded || 'Phone enrolled.';
                    preserveScrollAround(loadTiqrTokens);
                    notifySyncPending(result);
                    return;
                }
            } catch (e) {
                // A single failed poll is not worth aborting the whole
                // enrollment over; the next tick tries again.
            }
            tiqrPollTimer = setTimeout(tick, 2000);
        }

        tiqrPollTimer = setTimeout(tick, 2000);
    }

    function cancelTiqrEnrollment() {
        stopTiqrPolling();
        showTiqrEnrollBox(false);
        const statusEl = document.getElementById('tiqrStatus');
        if (statusEl) statusEl.textContent = '';
    }

    async function toggleTiqrToken(name, enabled) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const resp = await fetchJSON(urls.urlToggleTiqr, {
            method: 'POST',
            body: JSON.stringify({name: name, enabled: enabled}),
        });
        const result = await resp.json();
        if (!resp.ok) {
            throw new Error(result.error || i18n.labelFailedToggleTiqr || 'Failed to update phone.');
        }
        return !!result.enabled;
    }

    async function deleteTiqrToken(name, label) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const tpl = i18n.labelConfirmDeleteTiqr || 'Remove phone "{name}"?';
        if (!confirm(interpolate(tpl, {name: label}))) {
            return;
        }
        const statusEl = document.getElementById('tiqrStatus');
        const errorEl = document.getElementById('tiqrError');
        errorEl.textContent = '';
        try {
            const resp = await fetchJSON(urls.urlDelTiqr, {
                method: 'POST',
                body: JSON.stringify({name: name}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedDeleteTiqr || 'Failed to remove phone.');
            }
            statusEl.textContent = i18n.labelTiqrDeleted || 'Phone removed.';
            preserveScrollAround(loadTiqrTokens);
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelFailedDeleteTiqr || 'Failed to remove phone.';
        }
    }

    // Shared by every card whose tokens may hold the SSO role. The card
    // only says where to write status and errors; everything else about
    // a promotion is the same whether the thing being promoted is a
    // phone or a security key.
    async function promoteToken(name, label, ssoToken, {statusId, errorId}) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const tpl = i18n.labelConfirmPromoteTiqr
                || 'Make "{name}" your default token? Your current one keeps working under a new name.';
        if (!confirm(interpolate(tpl, {name: label}))) {
            return;
        }
        const statusEl = document.getElementById(statusId);
        const errorEl = document.getElementById(errorId);
        errorEl.textContent = '';
        // The name the current SSO token continues under. When it
        // brought its own label there is nothing to ask -- it keeps
        // being called what its owner calls it. We only ask when the
        // server had to make one up, because then the user would
        // otherwise go looking for a name they never saw.
        const body = {name: name};
        if (ssoToken && ssoToken.name && ssoToken.ask_label === false
        && ssoToken.suggested) {
            body.old_name = ssoToken.suggested;
        } else if (ssoToken && ssoToken.name) {
            const nameTpl = i18n.labelPromptOldTiqrName
                    || 'Name for your current default token ("{name}"), which keeps working:';
            // What goes in here is a label, the same thing the add
            // dialogs ask for -- the server puts the type prefix on it
            // (fido2-, tiqr-) the way it does when a token is added.
            // Showing the prefixed name instead would come back
            // through the same sanitizer and end up as
            // "fido2-fido2something" for anyone who just presses OK.
            //
            // The question names the token by its own label, which is
            // often the SSO name it is losing -- so what is prefilled
            // is the one the server made up, not that.
            const answer = prompt(
                    interpolate(nameTpl, {name: ssoToken.label || ssoToken.name}),
                    ssoToken.suggested || '');
            // Cancelled: the whole promotion is off. Sending none would
            // silently let the server pick instead.
            if (answer === null) {
                return;
            }
            if (!answer.trim()) {
                errorEl.textContent = i18n.labelNeedOldTiqrName
                        || 'Please enter a name for your current default token.';
                return;
            }
            body.old_name = answer.trim();
        }
        try {
            const resp = await fetchJSON(urls.urlPromoteToken, {
                method: 'POST',
                body: JSON.stringify(body),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedPromoteTiqr || 'Failed to change the default token.');
            }
            statusEl.textContent = i18n.labelTiqrPromoted || 'Default token changed.';
            // The token that just lost the role may sit on the other
            // card, so redraw both -- not only the one the button was
            // on.
            preserveScrollAround(async () => {
                await loadTiqrTokens();
                await loadFido2Tokens();
            });
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelFailedPromoteTiqr || 'Failed to change the default token.';
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
            const {body, error} = await window.readJsonResponse(
                resp,
                i18n.labelAdminAccessFailedLoad || 'Failed to load admin access state.');
            if (error) {
                throw new Error(error);
            }
            // available=false → admin_access_role unresolvable for this
            // user; hide the entire card.
            if (!body.available) {
                card.classList.add('is-hidden');
                return;
            }
            toggle.checked = !!body.enabled;
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
            const {body, error} = await window.readJsonResponse(
                resp,
                i18n.labelAdminAccessFailedSave || 'Failed to update admin access.');
            if (error) {
                throw new Error(error);
            }
            // Re-sync from server: handles the (rare) case where the
            // server clipped/overrode the request.
            toggle.checked = !!body.enabled;
            statusEl.textContent = body.enabled
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

    // ---- Recovery mail (SSO-token recovery destination) ----
    //
    // Two DOM subtrees, one visible at a time:
    //   * display: current value as text + small Edit button
    //   * edit:    input + small Save/Remove/Cancel
    // Edit click redirects through /reauth?next=/settings#recoveryMailCard;
    // after the reauth completes the user lands back here and the URL
    // hash flips the card into edit mode. The server gates every
    // write on session.reauth_time freshness -- if the window
    // elapsed by the time Save is clicked, the response carries
    // step_up_required=true and we bounce the user through /reauth
    // again.

    let _recoveryMailCurrentValue = null;
    // How long a step-up stays fresh, and when the last one happened.
    // ssod hands the window down with the address (sso_reauth_timeout);
    // the moment comes from landing back on this page after /reauth,
    // which is the same moment ssod bumped session.reauth_time.
    //
    // Without these every Edit click walked through /reauth again,
    // even one made a second after the last one -- ssod would have
    // accepted the write, it was simply never asked.
    let _stepUpMaxAge = 0;
    let _stepUpAt = 0;
    // Leave a little of the window unused rather than send a write
    // that is about to go stale. Landing in the step_up_required
    // fallback would work, but it costs the user a round trip and
    // another scan.
    const STEP_UP_MARGIN_MS = 5000;

    function _stepUpStillFresh() {
        if (!_stepUpMaxAge || !_stepUpAt) return false;
        const age = Date.now() - _stepUpAt;
        return age < (_stepUpMaxAge * 1000) - STEP_UP_MARGIN_MS;
    }

    function _recoveryMailEls() {
        return {
            card:       document.getElementById('recoveryMailCard'),
            display:    document.getElementById('recoveryMailDisplay'),
            edit:       document.getElementById('recoveryMailEdit'),
            valueEl:    document.getElementById('recoveryMailValue'),
            input:      document.getElementById('recoveryMailInput'),
            editBtn:    document.getElementById('editRecoveryMailBtn'),
            saveBtn:    document.getElementById('saveRecoveryMailBtn'),
            removeBtn:  document.getElementById('removeRecoveryMailBtn'),
            cancelBtn:  document.getElementById('cancelRecoveryMailBtn'),
            statusEl:   document.getElementById('recoveryMailStatus'),
            errorEl:    document.getElementById('recoveryMailError'),
        };
    }

    function _renderRecoveryMailDisplay(els) {
        const i18n = getPageI18n();
        const v = _recoveryMailCurrentValue;
        if (v) {
            els.valueEl.textContent = v;
            els.valueEl.classList.remove('empty');
            els.removeBtn.classList.remove('is-hidden');
        } else {
            els.valueEl.textContent = i18n.labelRecoveryMailNone
                    || 'No recovery address set.';
            els.valueEl.classList.add('empty');
            els.removeBtn.classList.add('is-hidden');
        }
        els.display.classList.remove('is-hidden');
        els.edit.classList.add('is-hidden');
    }

    function _enterRecoveryMailEdit(els) {
        els.input.value = _recoveryMailCurrentValue || '';
        els.display.classList.add('is-hidden');
        els.edit.classList.remove('is-hidden');
        if (_recoveryMailCurrentValue) {
            els.removeBtn.classList.remove('is-hidden');
        } else {
            els.removeBtn.classList.add('is-hidden');
        }
        els.input.focus();
    }

    // Send the user through /reauth and back to the card they were on.
    // The hash is what tells us, on the way back, that the step-up just
    // happened -- see loadRecoveryMail() and _noteStepUp().
    function _driveReauth(hash) {
        const urls = getUrls();
        const target = (urls.settingsPath || '/settings')
                + (hash || '#recoveryMailCard');
        window.location.assign(urls.urlReauth
                + '?next=' + encodeURIComponent(target));
    }

    async function loadRecoveryMail() {
        const urls = getUrls();
        const i18n = getPageI18n();
        const els = _recoveryMailEls();
        if (!els.card || !els.input) return;
        try {
            const resp = await fetchJSON(urls.urlGetRecoveryMail);
            const {body, error} = await window.readJsonResponse(
                resp,
                i18n.labelRecoveryMailFailedLoad || 'Failed to load recovery mail.');
            if (error) throw new Error(error);
            _recoveryMailCurrentValue = body.recovery_mail || null;
            _stepUpMaxAge = body.step_up_max_age || 0;
        } catch (e) {
            els.errorEl.textContent = e.message
                    || i18n.labelRecoveryMailFailedLoad
                    || 'Failed to load recovery mail.';
            return;
        }
        _renderRecoveryMailDisplay(els);
        // Coming back from /reauth for this card -- flip to edit mode.
        if (window.location.hash === '#recoveryMailCard') {
            _stepUpAt = Date.now();
            // Drop the hash again. It has done its job, and leaving it
            // would make a later reload look like another fresh
            // step-up -- the write would then be refused instead.
            history.replaceState(null, '', window.location.pathname
                                            + window.location.search);
            _enterRecoveryMailEdit(els);
        }
    }

    function onEditRecoveryMail() {
        // Still inside the window ssod will accept: no reason to send
        // the user through /reauth a second time. If it runs out while
        // they are typing, the save comes back with step_up_required
        // and _submitRecoveryMail() drives the reauth then.
        if (_stepUpStillFresh()) {
            _enterRecoveryMailEdit(_recoveryMailEls());
            return;
        }
        _driveReauth();
    }

    function onCancelRecoveryMail() {
        const els = _recoveryMailEls();
        els.errorEl.textContent = '';
        els.statusEl.textContent = '';
        _renderRecoveryMailDisplay(els);
    }

    // Client-side sanity mirror of stuff.is_email (server-side is
    // authoritative). Catches typos before the round-trip.
    function _looksLikeEmail(v) {
        if (typeof v !== 'string') return false;
        const s = v.trim();
        if (!s) return false;
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
    }

    async function _submitRecoveryMail(newValue) {
        const urls = getUrls();
        const i18n = getPageI18n();
        const els = _recoveryMailEls();
        els.statusEl.textContent = '';
        els.errorEl.textContent = '';
        els.saveBtn.disabled = true;
        els.removeBtn.disabled = true;
        els.cancelBtn.disabled = true;
        try {
            const resp = await fetchJSON(urls.urlSetRecoveryMail, {
                method: 'POST',
                body: JSON.stringify({recovery_mail: newValue || ''}),
            });
            const {body, error} = await window.readJsonResponse(
                resp,
                i18n.labelRecoveryMailFailedSave || 'Failed to save recovery mail.');
            // Server says the SSO-session reauth is stale -> drive the
            // user through /reauth and let them retry after landing back.
            if (body && body.step_up_required) {
                _driveReauth();
                return;
            }
            if (error) throw new Error(error);
            _recoveryMailCurrentValue = body.recovery_mail || null;
            els.statusEl.textContent = _recoveryMailCurrentValue
                    ? (i18n.labelRecoveryMailSaved || 'Recovery mail saved.')
                    : (i18n.labelRecoveryMailCleared || 'Recovery mail removed.');
            _renderRecoveryMailDisplay(els);
        } catch (e) {
            els.errorEl.textContent = e.message
                    || i18n.labelRecoveryMailFailedSave
                    || 'Failed to save recovery mail.';
        } finally {
            els.saveBtn.disabled = false;
            els.removeBtn.disabled = false;
            els.cancelBtn.disabled = false;
        }
    }

    async function onSaveRecoveryMail() {
        const i18n = getPageI18n();
        const els = _recoveryMailEls();
        const v = (els.input.value || '').trim();
        if (!v) {
            // Empty save is treated as an accidental "clear" -- use
            // the explicit Remove button for that instead.
            els.errorEl.textContent = i18n.labelRecoveryMailInvalid
                    || 'Please enter a valid e-mail address.';
            return;
        }
        if (!_looksLikeEmail(v)) {
            els.errorEl.textContent = i18n.labelRecoveryMailInvalid
                    || 'Please enter a valid e-mail address.';
            return;
        }
        await _submitRecoveryMail(v);
    }

    async function onRemoveRecoveryMail() {
        const i18n = getPageI18n();
        const els = _recoveryMailEls();
        const msg = i18n.labelConfirmRemoveRecoveryMail
                || 'Remove your recovery e-mail address?';
        if (!window.confirm(msg)) return;
        els.input.value = '';
        await _submitRecoveryMail('');
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

    function getSessionUrls() {
        const el = document.getElementById('session-urls');
        return el ? el.dataset : null;
    }

    function formatSessionTime(ts) {
        if (!ts) return '';
        try {
            return new Date(ts * 1000).toLocaleString();
        } catch (e) {
            return '';
        }
    }

    function sessionHint(text) {
        const hint = document.createElement('span');
        hint.className = 'hint is-block';
        hint.textContent = text;
        return hint;
    }

    async function loadSessions() {
        const urls = getSessionUrls();
        const i18n = getPageI18n();
        const card = document.getElementById('sessionCard');
        const listEl = document.getElementById('sessionList');
        if (!urls || !listEl) return;
        listEl.innerHTML = '';
        try {
            const resp = await fetchJSON(urls.urlList);
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedLoadSessions || 'Failed to load sessions.');
            }
            // Server gates the card on sso_allow_session_mgmt.
            if (result.allowed === false) {
                if (card) card.classList.add('is-hidden');
                return;
            }
            if (card) card.classList.remove('is-hidden');
            const sessions = result.sessions || [];
            if (sessions.length === 0) {
                const li = document.createElement('li');
                li.className = 'empty';
                li.textContent = i18n.labelNoSessions || 'No active sessions.';
                listEl.appendChild(li);
                return;
            }
            for (const s of sessions) {
                const li = document.createElement('li');
                const label = document.createElement('span');
                label.className = 'device-label';
                const head = document.createElement('strong');
                head.textContent = s.access_group || s.session_type || '';
                label.appendChild(head);
                if (s.current) {
                    const current = document.createElement('span');
                    current.className = 'hint';
                    current.textContent = ' (' + (i18n.labelCurrentSession || 'This session') + ')';
                    label.appendChild(current);
                }
                const where = [s.client, s.client_ip].filter(Boolean).join(', ');
                if (where) {
                    label.appendChild(sessionHint(
                            (i18n.labelSessionClientPrefix || 'Client:') + ' ' + where));
                }
                if (s.token) {
                    label.appendChild(sessionHint(
                            (i18n.labelSessionTokenPrefix || 'Token:') + ' ' + s.token));
                }
                if (s.creation_time) {
                    label.appendChild(sessionHint(
                            (i18n.labelSessionLoginPrefix || 'Login:')
                            + ' ' + formatSessionTime(s.creation_time)));
                }
                if (s.expire_time) {
                    label.appendChild(sessionHint(
                            (i18n.labelSessionExpiresPrefix || 'Expires:')
                            + ' ' + formatSessionTime(s.expire_time)));
                }
                li.appendChild(label);
                // No button for the session this page is served from:
                // ending it would log the user out from here.
                if (!s.current) {
                    const btn = document.createElement('button');
                    btn.type = 'button';
                    btn.className = 'btn btn-secondary btn-small';
                    btn.textContent = i18n.labelEndSessionBtn || 'End session';
                    btn.addEventListener('click', () => deleteSession(s.uuid));
                    li.appendChild(btn);
                }
                listEl.appendChild(li);
            }
        } catch (e) {
            const li = document.createElement('li');
            li.className = 'error-msg';
            li.textContent = e.message || i18n.labelFailedLoadSessions || 'Failed to load sessions.';
            listEl.appendChild(li);
        }
    }

    async function deleteSession(sessionUuid) {
        const urls = getSessionUrls();
        if (!urls) return;
        const i18n = getPageI18n();
        const msg = i18n.labelConfirmEndSession
                || 'End this session? Applications you signed in to with it will be signed out.';
        if (!confirm(msg)) {
            return;
        }
        const statusEl = document.getElementById('sessionStatus');
        const errorEl = document.getElementById('sessionError');
        statusEl.textContent = '';
        errorEl.textContent = '';
        try {
            const resp = await fetchJSON(urls.urlDelete, {
                method: 'POST',
                body: JSON.stringify({session_uuid: sessionUuid}),
            });
            const result = await resp.json();
            if (!resp.ok) {
                throw new Error(result.error || i18n.labelFailedEndSession || 'Failed to end session.');
            }
            statusEl.textContent = result.message || i18n.labelSessionEnded || 'Session ended.';
            preserveScrollAround(loadSessions);
        } catch (e) {
            errorEl.textContent = e.message || i18n.labelFailedEndSession || 'Failed to end session.';
        }
    }

    async function revokeOidcConsent(clientUuid, label) {
        const urls = getConsentUrls();
        if (!urls) return;
        const i18n = getPageI18n();
        const tpl = i18n.labelConfirmRevoke
                || 'Disconnect "{name}"? Active sessions for this application will be terminated.';
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
            preserveScrollAround(loadOidcConsents);
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

    // Preserve the current scroll position across an async reloader
    // call (loadDeviceTokens / loadPasskeys / loadOidcConsents). The
    // reloaders clear their container synchronously and re-fill it
    // after a fetch; without a snap-back the page can jump because
    // the layout collapses to zero height between clear and re-fill.
    async function preserveScrollAround(fn) {
        const y = window.scrollY;
        try {
            await fn();
        } finally {
            requestAnimationFrame(function () { window.scrollTo(0, y); });
        }
    }

    // Scroll-position persistence across reloads. The settings page
    // grows in height as the async loaders (device tokens, passkeys,
    // admin access, oidc consents) populate their cards, so the
    // browser's automatic scroll restoration fires too early -- the
    // anchor it lands on hasn't been rendered yet. We take over: save
    // the scroll position before unload and restore it after all
    // loaders settle.
    const SCROLL_KEY = 'settings:scrollY';

    window.addEventListener('beforeunload', function () {
        try {
            sessionStorage.setItem(SCROLL_KEY, String(window.scrollY));
        } catch (e) { /* sessionStorage disabled — give up silently */ }
    });

    // Take the loading overlay down and give scrolling back. Called
    // once, after every loader has settled -- see the comment on the
    // overlay in settings.html for why it is up in the first place.
    function endPageLoading() {
        document.body.classList.remove('is-loading');
        const overlay = document.getElementById('settingsLoading');
        if (overlay) overlay.classList.add('is-hidden');
    }

    document.addEventListener('DOMContentLoaded', function () {
        if ('scrollRestoration' in history) {
            history.scrollRestoration = 'manual';
        }
        // The overlay is rendered by the template; this is what stops
        // the page behind it from scrolling. Set here rather than in
        // the template because it belongs on <body>, which base.html
        // owns.
        document.body.classList.add('is-loading');
        // A fetch that never comes back would leave the page under the
        // overlay for good. Give up waiting after a while and show
        // what did arrive -- an incomplete page beats a locked one,
        // and endPageLoading() runs fine twice.
        setTimeout(endPageLoading, 15000);

        const pwBtn = document.getElementById('changePwBtn');
        if (pwBtn) pwBtn.addEventListener('click', changePassword);

        const pinBtn = document.getElementById('changePinBtn');
        if (pinBtn) pinBtn.addEventListener('click', changePin);

        const langBtn = document.getElementById('saveLanguageBtn');
        if (langBtn) langBtn.addEventListener('click', saveLanguage);

        // Device-token cards (add/copy buttons) are wired up per role
        // inside loadDeviceTokens() / buildRoleCard() since the count
        // and ids depend on the user's configured device_token_roles.
        const addPasskeyBtn = document.getElementById('addPasskeyBtn');
        if (addPasskeyBtn) addPasskeyBtn.addEventListener('click', addPasskey);
        const startPasskeyBtn = document.getElementById('startPasskeyBtn');
        if (startPasskeyBtn) startPasskeyBtn.addEventListener('click',
                () => onStartAdd('passkey'));

        const addFido2Btn = document.getElementById('addFido2Btn');
        if (addFido2Btn) addFido2Btn.addEventListener('click', addFido2Token);
        const startFido2Btn = document.getElementById('startFido2Btn');
        if (startFido2Btn) startFido2Btn.addEventListener('click',
                () => onStartAdd('fido2'));

        const addTiqrBtn = document.getElementById('addTiqrBtn');
        if (addTiqrBtn) addTiqrBtn.addEventListener('click', addTiqrToken);
        const tiqrCancelBtn = document.getElementById('tiqrCancelBtn');
        if (tiqrCancelBtn) tiqrCancelBtn.addEventListener('click', cancelTiqrEnrollment);
        const startTiqrBtn = document.getElementById('startTiqrBtn');
        if (startTiqrBtn) startTiqrBtn.addEventListener('click',
                () => onStartAdd('tiqr'));

        const adminToggle = document.getElementById('adminAccessToggle');
        if (adminToggle) adminToggle.addEventListener('change', onAdminAccessToggle);

        const editRecoveryBtn = document.getElementById('editRecoveryMailBtn');
        if (editRecoveryBtn) editRecoveryBtn.addEventListener('click', onEditRecoveryMail);
        const saveRecoveryBtn = document.getElementById('saveRecoveryMailBtn');
        if (saveRecoveryBtn) saveRecoveryBtn.addEventListener('click', onSaveRecoveryMail);
        const removeRecoveryBtn = document.getElementById('removeRecoveryMailBtn');
        if (removeRecoveryBtn) removeRecoveryBtn.addEventListener('click', onRemoveRecoveryMail);
        const cancelRecoveryBtn = document.getElementById('cancelRecoveryMailBtn');
        if (cancelRecoveryBtn) cancelRecoveryBtn.addEventListener('click', onCancelRecoveryMail);

        // Kick off all async loaders in parallel; catch each so a
        // single failure doesn't keep scroll restoration from firing.
        Promise.all([
            loadDeviceTokens().catch(() => {}),
            loadPasskeys().catch(() => {}),
            loadFido2Tokens().catch(() => {}),
            loadTiqrTokens().catch(() => {}),
            loadAdminAccess().catch(() => {}),
            loadRecoveryMail().catch(() => {}),
            loadOidcConsents().catch(() => {}),
            loadSessions().catch(() => {}),
        ]).then(function () {
            let saved = null;
            try {
                saved = sessionStorage.getItem(SCROLL_KEY);
                sessionStorage.removeItem(SCROLL_KEY);
            } catch (e) { /* sessionStorage disabled */ }
            const y = saved === null ? null : parseInt(saved, 10);
            // requestAnimationFrame to land after the post-load layout
            // pass has happened. Uncovering and scrolling go in the
            // same frame: uncovering first would show the page at the
            // top for one frame before it jumps.
            requestAnimationFrame(function () {
                endPageLoading();
                if (y !== null && Number.isFinite(y)) {
                    window.scrollTo(0, y);
                }
                // After the loaders: the device token cards, and the
                // buttons in them, only exist once loadDeviceTokens()
                // has built them.
                resumePendingAdd();
            });
        }).catch(function () {
            // Promise.all above catches each loader, so this only
            // fires on something unforeseen. Whatever it was, leaving
            // the page under a permanent overlay would be worse.
            endPageLoading();
        });
    });
})();
