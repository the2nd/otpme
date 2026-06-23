<?php
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$redirect_url = $_POST['redirect_url'] ?? '';
$app_name = $_POST['app_name'] ?? '';
$sso_popup = $_POST['sso_popup'] ?? false;
if (is_string($sso_popup)) {
    $sso_popup = ($sso_popup === 'true' || $sso_popup === '1');
}
$app_label = $app_name !== '' ? $app_name : 'Anwendung';
?><!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTPme SSO &ndash; <?php echo htmlspecialchars($app_label, ENT_QUOTES, 'UTF-8'); ?></title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        html, body {
            height: 100%;
            font-family: 'Segoe UI', Roboto, Arial, sans-serif;
            font-size: 15px;
            color: #333;
            background: #f0f2f5;
        }
        body {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }
        .sso-card {
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(0,0,0,.08);
            padding: 40px 36px 32px;
            width: 100%;
            max-width: 420px;
            text-align: center;
        }
        .sso-card h1 {
            font-size: 22px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #222;
        }
        .sso-app {
            font-size: 15px;
            color: #555;
            margin-bottom: 24px;
            word-break: break-word;
        }
        .sso-app strong { color: #222; }
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 12px 22px;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            background: #4a7cff;
            color: #fff;
            transition: background .15s, box-shadow .15s;
            width: 100%;
        }
        .btn:hover { background: #3a66dd; }
        .sso-countdown {
            margin-top: 18px;
            font-size: 13px;
            color: #666;
        }
        .spinner {
            width: 42px;
            height: 42px;
            margin: 6px auto 4px;
            border: 4px solid #e4e6ea;
            border-top-color: #4a7cff;
            border-radius: 50%;
            animation: sso-spin 0.9s linear infinite;
        }
        @keyframes sso-spin { to { transform: rotate(360deg); } }
    </style>
    <script>
        function setInputValue(input, value) {
            input.value = value;
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
            input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
        }

        async function handleLogin(newTab) {
            const username = <?php echo json_encode($username); ?>;
            const password = <?php echo json_encode($password); ?>;

            usernameInput = null;
            passwordInput = null;

            function checkForLoginForm() {
                const forms = newTab.document.getElementsByTagName('form');
                if (forms.length > 0) {
                    return forms;
                }
                return null;
            }

            const maxWait = 10000;
            const interval = 200;
            let waited = 0;
            // ``forms`` must be a proper local; reading an undeclared
            // identifier in the loop header throws ReferenceError in
            // both strict and sloppy mode -- the previous code only
            // appeared to work because cross-origin pages tripped
            // SecurityError before the loop ran.
            let forms = checkForLoginForm();
            while (!forms && waited < maxWait) {
                await new Promise(r => setTimeout(r, interval));
                forms = checkForLoginForm();
                waited += interval;
            }
            if (!forms) {
                console.error('No login form found within timeout.');
                return;
            }

            for (const form of forms) {
                const submitButton = form.querySelector('input[type="submit"], button[type="submit"]');
                const inputs = form.getElementsByTagName('input');
                for (const input of inputs) {
                    const type = input.type.toLowerCase();
                    if (type === 'text') {
                        usernameInput = input;
                        usernameInput.style.display = 'none';
                    } else if (type === 'password') {
                        passwordInput = input;
                        passwordInput.style.display = 'none';
                    }
                }

                if (usernameInput && passwordInput) {
                    usernameInput.setAttribute('autocomplete', 'off');
                    passwordInput.setAttribute('autocomplete', 'off');
                    setInputValue(usernameInput, username);
                    setInputValue(passwordInput, password);
                    submitButton.click();
                }
            }
            window.close();
        }

        async function openAndCheckWindow() {
            const redirectURL = <?php echo json_encode($redirect_url); ?>;
            const newTab = window.open(redirectURL, '_blank');
            if (newTab) {
                const checkIfLoaded = setInterval(function() {
                    try {
                        if (newTab.document.readyState === 'complete') {
                            clearInterval(checkIfLoaded);
                            handleLogin(newTab);
                        }
                    } catch (e) {
                        console.error(e);
                    }
                }, 1000);
            } else {
                console.error('Cannot open new tab. Popup-Blocker?.');
            }
        }

        // Auto-close countdown for the non-popup launcher tab.
        // Once the target app was opened in a new window the launcher
        // tab has no further purpose -- close it after 30 s so it
        // doesn't sit around as a dead tab in the user's browser.
        function startAutoClose(seconds) {
            const el = document.getElementById('countdown');
            let remaining = seconds;
            function render() {
                if (el) {
                    el.textContent = 'Dieses Fenster schließt sich automatisch in '
                                     + remaining + ' Sekunden.';
                }
            }
            render();
            const tick = setInterval(function() {
                remaining -= 1;
                if (remaining <= 0) {
                    clearInterval(tick);
                    window.close();
                    return;
                }
                render();
            }, 1000);
        }
    </script>
</head>
<body>
    <div class="sso-card">
        <?php if ($sso_popup): ?>
            <h1>Anmeldung wird gestartet&hellip;</h1>
            <p class="sso-app"><strong><?php echo htmlspecialchars($app_label, ENT_QUOTES, 'UTF-8'); ?></strong></p>
            <div class="spinner" aria-hidden="true"></div>
            <script>openAndCheckWindow();</script>
        <?php else: ?>
            <h1>Anwendung öffnen</h1>
            <p class="sso-app"><strong><?php echo htmlspecialchars($app_label, ENT_QUOTES, 'UTF-8'); ?></strong></p>
            <button type="button" class="btn" onclick="openAndCheckWindow()">
                <?php echo htmlspecialchars($app_label, ENT_QUOTES, 'UTF-8'); ?> öffnen
            </button>
            <p id="countdown" class="sso-countdown">
                Dieses Fenster schließt sich automatisch in 30 Sekunden.
            </p>
            <script>startAutoClose(30);</script>
        <?php endif; ?>
    </div>
</body>
</html>
