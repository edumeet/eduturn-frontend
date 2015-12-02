<?php
require_once('/usr/share/simplesamlphp/lib/_autoload.php');
$as = new SimpleSAML_Auth_Simple('default-sp');
$as->requireAuth();
$as->logout('https://brain.lab.vvc.niif.hu');
?>
