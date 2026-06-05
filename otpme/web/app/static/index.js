(function () {
    'use strict';

    function getI18n() {
        const el = document.getElementById('page-i18n');
        return el ? el.dataset : {};
    }

    function openTabAndSendPost(sso_url, data) {
        const newTab = window.open('', '_blank');
        if (newTab) {
            const form = newTab.document.createElement('form');
            form.method = 'POST';
            form.action = sso_url;
            form.target = '_top';
            for (const key in data) {
                const input = newTab.document.createElement('input');
                input.type = 'hidden';
                input.name = key;
                input.value = data[key];
                form.appendChild(input);
            }
            newTab.document.body.appendChild(form);
            // Defense in depth: even with target="_top" the spawned
            // tab inherits an `opener` reference that the destination
            // origin could navigate via window.opener.location. Null
            // it before submitting so a hostile RP can't tab-nab us.
            try { newTab.opener = null; } catch (e) { /* cross-origin */ }
            form.submit();
        }
    }

    function addApps() {
        const pageData = document.getElementById('page-data').dataset;
        const i18n = getI18n();
        const appsUrl = pageData.urlApps;
        const sotpUrl = pageData.urlSotp;
        const username = pageData.username;

        fetchJSON(appsUrl)
            .then(async response => {
                const data = await response.json();
                if (!response.ok) {
                    if (data && data.redirect) {
                        window.location.href = data.redirect;
                        return null;
                    }
                    throw new Error((data && data.error) || i18n.labelFailedApps || 'Failed to load apps.');
                }
                return data;
            })
            .then(data => {
                if (!data) return;
                const tileContainer = document.getElementById('app-tiles');

                data.forEach(item => {
                    const tile = document.createElement('div');
                    tile.classList.add('app-tile');

                    if (item.logo_type) {
                        const picElement = document.createElement('img');
                        picElement.src = "data:" + item.logo_type + ";base64," + item.logo_data;
                        picElement.alt = item.app_name || "App";
                        tile.appendChild(picElement);
                    }

                    if (item.app_name) {
                        const appNameElement = document.createElement('div');
                        appNameElement.classList.add('app-name');
                        appNameElement.textContent = item.app_name;
                        tile.appendChild(appNameElement);
                    }

                    const openButton = document.createElement('button');
                    openButton.textContent = i18n.labelOpen || 'Open';
                    openButton.classList.add('btn', 'btn-primary', 'btn-small');
                    openButton.addEventListener('click', () => {
                        // OIDC RPs handle SSO themselves -- the browser
                        // just needs to land on the RP, which then
                        // redirects to /oidc/authorize; the SSO cookie
                        // proves the user is already logged in.
                        if (item.oidc) {
                            window.open(item.login_url, '_blank');
                            return;
                        }
                        fetchJSON(sotpUrl, {
                                method: 'POST',
                                body: JSON.stringify({access_group: item.app_ag}),
                            })
                            .then(async response => {
                                const data = await response.json();
                                if (!response.ok) {
                                    if (data && data.redirect) {
                                        window.location.href = data.redirect;
                                        return null;
                                    }
                                    throw new Error((data && data.error) || i18n.labelFailedSotp || 'Failed to get SOTP.');
                                }
                                return data;
                            })
                            .then(sotp => {
                                if (!sotp) return;
                                const login_data = {
                                    username: username,
                                    password: sotp,
                                    redirect_url: item.login_url,
                                    sso_popup: item.sso_popup,
                                    app_name: item.app_name,
                                };
                                openTabAndSendPost(item.helper_url, login_data);
                            })
                            .catch(error => {
                                console.error('Error fetching SOTP:', error);
                            });
                    });
                    tile.appendChild(openButton);

                    tileContainer.appendChild(tile);
                });
            })
            .catch(error => {
                console.error('Error fetching apps:', error);
            });
    }

    document.addEventListener('DOMContentLoaded', addApps);
})();
