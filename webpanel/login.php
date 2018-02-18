<?php
$passwd = $_POST["password"];

if (hash("sha512", $passwd) == "02d568c0a86835a4c9cfe84733f318458657bdda1ba239444db9774518e390fe7a977b3a8b3f0d64778f4b82f3783bc251bc086187b34ffbefd8da95ba5865ba")
{
  echo "Ok!";
}
?>
