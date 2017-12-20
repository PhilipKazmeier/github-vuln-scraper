<?php

// Insert new visitor into table
$name = $_GET["name"];
$query = "INSERT INTO visitors(name) VALUES ($name);";
mysql_query($query);

// Perform the select with queried data
$offset = $_GET["offset"];
$query  = "SELECT id, name FROM products ORDER BY name LIMIT 20 OFFSET $offset;";
$result = mysql_query($query);

echo $result

?>
