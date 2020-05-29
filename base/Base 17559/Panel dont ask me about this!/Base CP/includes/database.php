<?php
$DB_HOST = "root.silent.hosted.nfoservers.com";
$DB_NAME = "silentwebhost_base";
$DB_USER = "silentwebhost";
$DB_PASS = "5oey5EsxBa";

$con = mysqli_connect($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);

if(mysqli_connect_errno())
{
	die("Not Connection To MySQL Database " . mysqli_connect_error());
}
?>


