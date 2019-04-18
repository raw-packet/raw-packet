<?php
if (isset($_POST['identifier'])) {
    $identifier = $_POST['identifier'];

    //send POST request to https://accounts.google.com/
    $url = 'https://accounts.google.com/_/signin/sl/lookup';

    $options = array(
        'http' => array(
            'header'  => "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:61.0) Gecko/20100101 Firefox/61.0\r\n" .
                "Accept: */*\r\n" .
                "Accept-Language: ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3\r\n" .
                "Accept-Encoding: gzip, deflate\r\n" .
                "X-Same-Domain: 1\r\n" .
                "Google-Accounts-XSRF: 1\r\n" .
                "Content-Type: application/x-www-form-urlencoded\r\n" .
                "Connection: close\r\n",
            'method'  => 'POST',
            'content' => 'f.req=["' . $identifier . '"]',
        ),
        'ssl' => array(
            'verify_peer' => false,
        ),
    );

    $context  = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    //echo $result;

    //parse reply
    if ($result == false) {
        echo "ERROR";
    }
    else {
        $result_strings = explode(",", $result);
        foreach ($result_strings as &$result_string) {
            if (preg_match('/"(' . $identifier . '.*)"/i', $result_string,$match_string)) {
                if (isset($match_string[1])) {
                    echo $match_string[1];
                    exit();
                }
            }
        }
        echo "ERROR";
    }
}
else {
    echo "ERROR";
}
exit();
