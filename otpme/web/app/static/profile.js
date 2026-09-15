(function () {
    'use strict';

    function getUrls() {
        return document.getElementById('page-data').dataset;
    }

    function getPageI18n() {
        const el = document.getElementById('page-i18n');
        return el ? el.dataset : {};
    }

    function getAttributeLabels() {
        try {
            return JSON.parse(getUrls().attributeLabels || '{}');
        } catch (e) {
            return {};
        }
    }

    // What an edit was about when a fresh step-up had to come first
    // (sso_profile_edit_reauth). Kept across the trip to /reauth so that
    // coming back opens the same editor, with what was typed into it.
    // sessionStorage: per tab, gone with it; nothing in here is more
    // than what the page shows anyway.
    const PENDING_KEY = 'otpme-profile-pending-edit';
    // A reauth takes a scan or a key touch. Anything older is somebody
    // coming back to the page for another reason.
    const PENDING_MAX_AGE_MS = 5 * 60 * 1000;
    const REAUTH_HASH = '#profile';
    // PROFILE_MAX_PHOTO_UPLOAD_SIZE in ssod, which decides. Checked here
    // only to spare the upload.
    const MAX_PHOTO_SIZE = 8 * 1024 * 1024;
    const TIMESTAMP_ATTRIBUTES = ['createTimestamp', 'modifyTimestamp'];

    let profile = {attributes: {}, order: [], editable: [], single_valued: [], photo: null};

    // {name} placeholders, filled in here -- see interpolate() in
    // settings.js for why not %(name)s.
    function interpolate(template, vars) {
        return template.replace(/\{(\w+)\}/g, (m, k) =>
                (vars[k] !== undefined ? vars[k] : ''));
    }

    function button(label, className, onClick) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = className;
        btn.textContent = label;
        btn.addEventListener('click', onClick);
        return btn;
    }

    function clearMessages() {
        for (const id of ['profileStatus', 'profileError',
                          'profilePhotoStatus', 'profilePhotoError']) {
            const el = document.getElementById(id);
            if (el) el.textContent = '';
        }
    }

    function setMessage(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = text || '';
    }

    // Send the user through /reauth and back here, and remember what
    // they were about to change -- see resumePendingEdit().
    function driveReauth(pending) {
        try {
            sessionStorage.setItem(PENDING_KEY, JSON.stringify(
                    Object.assign({at: Date.now()}, pending)));
        } catch (e) { /* sessionStorage disabled: press edit again */ }
        const urls = getUrls();
        window.location.assign(urls.urlReauth + '?next='
                + encodeURIComponent(urls.profilePath + REAUTH_HASH));
    }

    // Asked when an edit button is pressed, like the add buttons of the
    // settings page, so the user proves themselves before typing rather
    // than after. A failed question opens the editor anyway: the save
    // is refused without the step-up and asks for it then.
    async function stepUpMissing() {
        try {
            const resp = await fetchJSON(getUrls().urlStepUpState);
            const body = await resp.json();
            if (resp.ok) return !!(body.step_up_missing || {}).profile;
        } catch (e) { /* see above */ }
        return false;
    }

    function formatValue(attribute, value) {
        if (TIMESTAMP_ATTRIBUTES.includes(attribute) && /^\d+$/.test(value)) {
            return new Date(parseInt(value, 10) * 1000).toLocaleString();
        }
        return value;
    }

    // ---- Photo ----

    function photoEls() {
        return {
            img:        document.getElementById('profilePhotoImg'),
            none:       document.getElementById('profilePhotoNone'),
            editBtn:    document.getElementById('editPhotoBtn'),
            edit:       document.getElementById('profilePhotoEdit'),
            input:      document.getElementById('profilePhotoInput'),
            saveBtn:    document.getElementById('savePhotoBtn'),
            removeBtn:  document.getElementById('removePhotoBtn'),
            cancelBtn:  document.getElementById('cancelPhotoBtn'),
        };
    }

    function showPhotoEdit(open) {
        const els = photoEls();
        const editable = profile.editable.includes('jpegPhoto');
        els.edit.classList.toggle('is-hidden', !open);
        els.editBtn.classList.toggle('is-hidden', open || !editable);
        els.removeBtn.classList.toggle('is-hidden', !profile.photo);
        if (open) els.input.value = '';
    }

    function renderPhoto() {
        const els = photoEls();
        if (profile.photo) {
            els.img.src = 'data:image/jpeg;base64,' + profile.photo;
            els.img.classList.remove('is-hidden');
            els.none.classList.add('is-hidden');
        } else {
            els.img.removeAttribute('src');
            els.img.classList.add('is-hidden');
            els.none.classList.remove('is-hidden');
        }
        showPhotoEdit(false);
    }

    async function onEditPhoto() {
        clearMessages();
        if (await stepUpMissing()) {
            driveReauth({photo: true});
            return;
        }
        showPhotoEdit(true);
    }

    function readFileBase64(file) {
        return new Promise(function (resolve, reject) {
            const reader = new FileReader();
            reader.onload = function () {
                const result = String(reader.result);
                resolve(result.slice(result.indexOf(',') + 1));
            };
            reader.onerror = function () {
                reject(reader.error);
            };
            reader.readAsDataURL(file);
        });
    }

    async function submitPhoto(photo) {
        const i18n = getPageI18n();
        const els = photoEls();
        clearMessages();
        const buttons = [els.saveBtn, els.removeBtn, els.cancelBtn];
        buttons.forEach(b => { b.disabled = true; });
        try {
            let resize = false;
            let body = null;
            for (;;) {
                const resp = await fetchJSON(getUrls().urlSetPhoto, {
                    method: 'POST',
                    body: JSON.stringify({photo: photo, resize: resize}),
                });
                const result = await window.readJsonResponse(resp,
                        i18n.labelFailedSavePhoto || 'Failed to save photo.');
                body = result.body;
                // The reauth ran out on the way. The file has to be
                // chosen again after it, a file input cannot be filled
                // in for the user.
                if (body && body.step_up_required) {
                    driveReauth({photo: true});
                    return;
                }
                if (result.error) throw new Error(result.error);
                // Not the size photos have here (user_photo_dimensions).
                // Nothing is stored until the user agrees to the resize.
                if (!body.resize_required || resize) break;
                const question = interpolate(i18n.labelConfirmResizePhoto
                        || 'The photo is {photo_dimensions}, photos here are {dimensions}. Resize it?',
                        body);
                if (!window.confirm(question)) {
                    setMessage('profilePhotoError', interpolate(
                            i18n.labelPhotoWrongDimensions
                            || 'The photo must be {dimensions}.', body));
                    return;
                }
                resize = true;
            }
            profile.photo = body.photo || null;
            renderPhoto();
            setMessage('profilePhotoStatus', photo
                    ? (i18n.labelPhotoSaved || 'Photo saved.')
                    : (i18n.labelPhotoRemoved || 'Photo removed.'));
        } catch (e) {
            setMessage('profilePhotoError', e.message
                    || i18n.labelFailedSavePhoto || 'Failed to save photo.');
        } finally {
            buttons.forEach(b => { b.disabled = false; });
        }
    }

    async function onSavePhoto() {
        const i18n = getPageI18n();
        const els = photoEls();
        clearMessages();
        const file = els.input.files && els.input.files[0];
        if (!file) {
            setMessage('profilePhotoError', i18n.labelNoPhotoChosen
                    || 'Please choose a photo first.');
            return;
        }
        if (file.type && file.type !== 'image/jpeg') {
            setMessage('profilePhotoError', i18n.labelPhotoNotJpeg
                    || 'The photo must be a JPEG image.');
            return;
        }
        if (file.size > MAX_PHOTO_SIZE) {
            setMessage('profilePhotoError', i18n.labelPhotoTooLarge
                    || 'The photo is too large.');
            return;
        }
        let photo;
        try {
            photo = await readFileBase64(file);
        } catch (e) {
            setMessage('profilePhotoError', i18n.labelFailedSavePhoto
                    || 'Failed to save photo.');
            return;
        }
        await submitPhoto(photo);
    }

    async function onRemovePhoto() {
        const i18n = getPageI18n();
        if (!window.confirm(i18n.labelConfirmRemovePhoto || 'Remove your photo?')) {
            return;
        }
        await submitPhoto('');
    }

    function onCancelPhoto() {
        clearMessages();
        showPhotoEdit(false);
    }

    // ---- Attributes ----

    // In the order ssod gives (sso_profile_attributes), set or not.
    function attributeNames() {
        return profile.order;
    }

    function findRow(attribute) {
        const rows = document.querySelectorAll('#profileAttributeList li');
        for (const li of rows) {
            if (li.dataset.attribute === attribute) return li;
        }
        return null;
    }

    function renderAttributeDisplay(li) {
        const i18n = getPageI18n();
        const attribute = li.dataset.attribute;
        const body = li.querySelector('.profile-attribute-body');
        body.textContent = '';
        const valuesEl = document.createElement('div');
        valuesEl.className = 'profile-attribute-values';
        const values = profile.attributes[attribute] || [];
        if (values.length === 0) {
            const empty = document.createElement('span');
            empty.className = 'profile-attribute-empty';
            empty.textContent = i18n.labelNotSet || 'Not set';
            valuesEl.appendChild(empty);
        }
        for (const value of values) {
            const el = document.createElement('div');
            el.textContent = formatValue(attribute, value);
            valuesEl.appendChild(el);
        }
        body.appendChild(valuesEl);
        if (profile.editable.includes(attribute)) {
            body.appendChild(button(i18n.labelEdit || 'Edit',
                    'btn btn-secondary btn-small',
                    () => onEditAttribute(attribute)));
        }
    }

    function renderAttributes() {
        const labels = getAttributeLabels();
        const list = document.getElementById('profileAttributeList');
        list.textContent = '';
        for (const attribute of attributeNames()) {
            const li = document.createElement('li');
            li.dataset.attribute = attribute;
            const head = document.createElement('div');
            head.className = 'profile-attribute-name';
            const label = document.createElement('span');
            label.className = 'profile-attribute-label';
            label.textContent = labels[attribute] || attribute;
            head.appendChild(label);
            // The LDAP name as well, for whoever has to tell the
            // administrator which one is wrong.
            if (labels[attribute]) {
                const ldapName = document.createElement('span');
                ldapName.className = 'profile-attribute-ldap-name';
                ldapName.textContent = attribute;
                head.appendChild(ldapName);
            }
            li.appendChild(head);
            const body = document.createElement('div');
            body.className = 'profile-attribute-body';
            li.appendChild(body);
            renderAttributeDisplay(li);
            list.appendChild(li);
        }
    }

    function openAttributeEditor(attribute, values) {
        const li = findRow(attribute);
        if (!li) return;
        const i18n = getPageI18n();
        const single = profile.single_valued.includes(attribute);
        const body = li.querySelector('.profile-attribute-body');
        body.textContent = '';
        const edit = document.createElement('div');
        edit.className = 'profile-attribute-edit settings-form';
        const inputs = document.createElement('div');
        inputs.className = 'profile-attribute-inputs';
        edit.appendChild(inputs);

        function addInput(value) {
            const row = document.createElement('div');
            row.className = 'profile-value-row';
            const input = document.createElement('input');
            input.type = 'text';
            input.spellcheck = false;
            input.value = value || '';
            row.appendChild(input);
            if (!single) {
                row.appendChild(button(i18n.labelRemove || 'Remove',
                        'btn btn-secondary btn-small',
                        () => row.remove()));
            }
            inputs.appendChild(row);
            return input;
        }

        let first = null;
        const start = (values && values.length) ? values : [''];
        for (const value of start) {
            const input = addInput(value);
            if (!first) first = input;
        }

        const actions = document.createElement('div');
        actions.className = 'recovery-mail-actions';
        if (!single) {
            actions.appendChild(button(i18n.labelAddValue || 'Add value',
                    'btn btn-secondary btn-small',
                    () => addInput('').focus()));
        }
        actions.appendChild(button(i18n.labelSave || 'Save',
                'btn btn-primary btn-small',
                () => saveAttribute(attribute, li)));
        actions.appendChild(button(i18n.labelCancel || 'Cancel',
                'btn btn-secondary btn-small',
                () => { clearMessages(); renderAttributeDisplay(li); }));
        edit.appendChild(actions);

        const errorEl = document.createElement('div');
        errorEl.className = 'error-msg profile-attribute-error';
        edit.appendChild(errorEl);

        body.appendChild(edit);
        if (first) first.focus();
    }

    async function onEditAttribute(attribute) {
        clearMessages();
        const values = profile.attributes[attribute] || [];
        if (await stepUpMissing()) {
            driveReauth({attribute: attribute, values: values});
            return;
        }
        openAttributeEditor(attribute, values);
    }

    async function saveAttribute(attribute, li) {
        const i18n = getPageI18n();
        clearMessages();
        const errorEl = li.querySelector('.profile-attribute-error');
        if (errorEl) errorEl.textContent = '';
        const values = Array.from(li.querySelectorAll('.profile-value-row input'))
                .map(input => input.value.trim())
                .filter(value => value !== '');
        const buttons = li.querySelectorAll('button');
        buttons.forEach(b => { b.disabled = true; });
        try {
            const resp = await fetchJSON(getUrls().urlSetAttribute, {
                method: 'POST',
                body: JSON.stringify({attribute: attribute, values: values}),
            });
            const {body, error} = await window.readJsonResponse(resp,
                    i18n.labelFailedSave || 'Failed to save profile.');
            // The reauth ran out while the user was typing.
            if (body && body.step_up_required) {
                driveReauth({attribute: attribute, values: values});
                return;
            }
            if (error) throw new Error(error);
            // Loaded again rather than patched in: other attributes may
            // follow the one changed (cn from givenName and sn).
            await loadProfile();
            setMessage('profileStatus', i18n.labelSaved || 'Saved.');
        } catch (e) {
            if (errorEl) {
                errorEl.textContent = e.message
                        || i18n.labelFailedSave || 'Failed to save profile.';
            }
            buttons.forEach(b => { b.disabled = false; });
        }
    }

    async function loadProfile() {
        const i18n = getPageI18n();
        const resp = await fetchJSON(getUrls().urlGetProfile);
        const {body, error} = await window.readJsonResponse(resp,
                i18n.labelFailedLoad || 'Failed to load profile.');
        if (error) throw new Error(error);
        profile = {
            attributes:     body.attributes || {},
            order:          body.order || [],
            editable:       body.editable || [],
            single_valued:  body.single_valued || [],
            photo:          body.photo || null,
        };
        renderPhoto();
        renderAttributes();
    }

    // Back from /reauth: open what the user was about to edit. Only when
    // we landed with the hash the trip was started with -- that is what
    // says the reauth actually happened.
    function resumePendingEdit() {
        let pending = null;
        try {
            pending = JSON.parse(sessionStorage.getItem(PENDING_KEY));
            sessionStorage.removeItem(PENDING_KEY);
        } catch (e) {
            return;
        }
        if (window.location.hash !== REAUTH_HASH) return;
        // It has done its job. Leaving it would make a reload look like
        // another trip back from /reauth.
        history.replaceState(null, '', window.location.pathname
                                        + window.location.search);
        if (!pending) return;
        if (Date.now() - (pending.at || 0) > PENDING_MAX_AGE_MS) return;
        if (pending.photo) {
            if (!profile.editable.includes('jpegPhoto')) return;
            showPhotoEdit(true);
            document.getElementById('profilePhotoCard').scrollIntoView();
            return;
        }
        if (!pending.attribute) return;
        if (!profile.editable.includes(pending.attribute)) return;
        openAttributeEditor(pending.attribute, pending.values || []);
        const li = findRow(pending.attribute);
        if (li) li.scrollIntoView({block: 'center'});
    }

    document.addEventListener('DOMContentLoaded', function () {
        const els = photoEls();
        els.editBtn.addEventListener('click', onEditPhoto);
        els.saveBtn.addEventListener('click', onSavePhoto);
        els.removeBtn.addEventListener('click', onRemovePhoto);
        els.cancelBtn.addEventListener('click', onCancelPhoto);

        loadProfile().then(resumePendingEdit).catch(function (e) {
            const i18n = getPageI18n();
            setMessage('profileError', e.message
                    || i18n.labelFailedLoad || 'Failed to load profile.');
        });
    });
})();
