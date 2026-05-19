(function () {
    'use strict';

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
            form.submit();
        }
    }

    function addApps() {
        const pageData = document.getElementById('page-data').dataset;
        const appsUrl = pageData.urlApps;
        const sotpUrl = pageData.urlSotp;
        const username = pageData.username;

        fetch(appsUrl)
            .then(async response => {
                const data = await response.json();
                if (!response.ok) {
                    if (data && data.redirect) {
                        window.location.href = data.redirect;
                        return null;
                    }
                    throw new Error((data && data.error) || 'Failed to load apps.');
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
                    openButton.textContent = 'Open';
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
                        const url = sotpUrl + "?access_group=" + encodeURIComponent(item.app_ag);
                        fetch(url)
                            .then(async response => {
                                const data = await response.json();
                                if (!response.ok) {
                                    if (data && data.redirect) {
                                        window.location.href = data.redirect;
                                        return null;
                                    }
                                    throw new Error((data && data.error) || 'Failed to get SOTP.');
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
