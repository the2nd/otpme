<?php
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$redirect_url = $_POST['redirect_url'] ?? '';
//$url_path = $_POST['url_path'] ?? '';

$username = htmlspecialchars($username);
$password = htmlspecialchars($password);
$redirect_url = htmlspecialchars($redirect_url);
//$url_path = htmlspecialchars($url_path);
$url_path = "/";

//echo "username: " . $username . "<br>";
//echo "password: " . $password;
$expire = time() + 30;
setcookie("username", $username, $expire, $url_path);
setcookie("password", $password, $expire, $url_path);
setcookie("redirect_url", $redirect_url, $expire, $url_path);
setcookie("url_path", $url_path, $expire, $url_path);
?>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script>
	function getCookie(name) {
	    let cookieArr = document.cookie.split(";");
	    for (let i = 0; i < cookieArr.length; i++) {
		let cookiePair = cookieArr[i].split("=");

		if (name === cookiePair[0].trim()) {
		    return decodeURIComponent(cookiePair[1]);
		}
	    }
	    return null;
	}

	function deleteCookie(name, path) {
	    document.cookie = name + "=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=" + path + ";";
	}

	function sleepThenDo(callback) {
		  setTimeout(callback, 1000);
	}

	function setInputValue(input, value) {
	  // Setze den Wert
	  input.value = value;
	  
	  // Löse verschiedene Events aus
	  input.dispatchEvent(new Event('input', { bubbles: true }));
	  input.dispatchEvent(new Event('change', { bubbles: true }));
	  input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
	}

	async function handleLogin(newTab) {
		let usernameCookie = getCookie("username");
		let passwordCookie = getCookie("password");
		let urlPath = getCookie("url_path");
		deleteCookie('username', urlPath);
		deleteCookie('password', urlPath);

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
						//usernameInput.style.display = 'none';
					} else if (type === 'password') {
						passwordInput = input;
						//passwordInput.style.display = 'none';
					}
				}

				if (usernameInput && passwordInput) {
				      	usernameInput.setAttribute('autocomplete', 'off');
				      	passwordInput.setAttribute('autocomplete', 'off');
					setInputValue(usernameInput, usernameCookie);
					setInputValue(passwordInput, passwordCookie);
				      	//usernameInput.value = usernameCookie;
				      	//passwordInput.value = passwordCookie;
				      	submitButton.click();
				      	//form.submit();
				}
			}
			window.close();
		//});
	}

	async function openAndCheckWindow() {
		let redirectURL = getCookie("redirect_url");
		let urlPath = getCookie("url_path");
		deleteCookie('redirect_url', urlPath);
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
	<h1>Starting login process...</h1>
	<script>
		openAndCheckWindow();
	</script>
</body>
</html>
