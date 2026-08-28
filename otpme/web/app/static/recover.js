(function () {
    'use strict';

    function getUrls() { return document.getElementById('page-data').dataset; }
    function getI18n() {
        const el = document.getElementById('page-i18n');
        return el ? el.dataset : {};
    }

    async function submitRecover() {
        const urls = getUrls();
        const i18n = getI18n();
        const statusEl = document.getElementById('recoverStatus');
        const errorEl = document.getElementById('recoverError');
        const formBlock = document.getElementById('recover-form-block');
        const sentBlock = document.getElementById('recover-sent-block');
        const sentMsg = document.getElementById('recoverSentMsg');
        const btn = document.getElementById('recoverSubmitBtn');

        statusEl.textContent = '';
        errorEl.textContent = '';

        const username = (document.getElementById('recoverUsername').value || '').trim();
        if (!username) {
            errorEl.textContent = i18n.labelNeedUsername || 'Please enter your username.';
            return;
        }

        btn.disabled = true;
        statusEl.textContent = i18n.labelSubmitting || 'Submitting request...';

        try {
            const resp = await fetchJSON(urls.urlRecover, {
                method: 'POST',
                body: JSON.stringify({username: username}),
            });
            const {body, error} = await window.readJsonResponse(
                resp,
                i18n.labelFailedSubmit || 'Failed to submit recovery request.');
            if (error) {
                throw new Error(error);
            }
            // Swap form for generic confirmation. Even when the account
            // does not exist we land here -- deliberate: response shape
            // is uniform to prevent user enumeration.
            statusEl.textContent = '';
            formBlock.classList.add('is-hidden');
            sentMsg.textContent = i18n.labelGenericSent
                    || 'If an account with the given username exists, a re-deploy link is on its way.';
            sentBlock.classList.remove('is-hidden');
        } catch (e) {
            errorEl.textContent = e.message
                    || i18n.labelFailedSubmit
                    || 'Failed to submit recovery request.';
            statusEl.textContent = '';
            btn.disabled = false;
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        const btn = document.getElementById('recoverSubmitBtn');
        if (btn) btn.addEventListener('click', submitRecover);
        const input = document.getElementById('recoverUsername');
        if (input) {
            input.addEventListener('keypress', function (e) {
                if (e.key === 'Enter') submitRecover();
            });
        }
    });
})();
