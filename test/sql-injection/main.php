<?php

$var = $_POST['var'];
mysql_query("SELECT * FROM sometable WHERE id = $var");

?>
