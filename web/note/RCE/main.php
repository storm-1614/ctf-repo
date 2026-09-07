<?php

$cmd = $_GET['x'];
$blacklist = [' ', 'cat', '/', ';', '|', '&'];

foreach ($blacklist as $bad) {
    if (strpos($cmd, $bad) !== false) {
        die("blocked: " . $bad);
    }
}

system("echo " . $cmd);

