<?php
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$redirect_url = $_POST['redirect_url'] ?? '';
$app_name = $_POST['app_name'] ?? '';
$sso_popup = $_POST['sso_popup'] ?? false;
if (is_string($sso_popup)) {
    $sso_popup = ($sso_popup === 'true' || $sso_popup === '1');
}
?>

<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script>
	//function sleepThenDo(callback) {
	//  setTimeout(callback, 1000);
	//}

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
			if (forms) {
				return forms;
			}
		}

		while (1 == 1) {
			forms = checkForLoginForm();
			if (forms) {
				break;
			}
		}

		//sleepThenDo(() => {
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
		//});
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
    </script>
</head>

<body>
	<?php if ($sso_popup): ?>
		<h1>Starting login process...</h1>
		<script>
			openAndCheckWindow();
		</script>
	<?php else: ?>
		<button onclick="openAndCheckWindow()">Open <?php echo $app_name;?></button>
	<?php endif; ?>
</body>
</html>
