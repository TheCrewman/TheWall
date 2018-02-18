<?php
$db = new PDO("sqlite:/home/pi/TheWall/logs/db/adsmasher.db");

$all_logs = $db->query("SELECT * FROM logs");
foreach ($all_logs as $single_log)
{
  if ($single_log["Counter"] != 0)
  {
    echo "DNS requests blocked for ".$single_log["Blacklisted_URL"].": ".$single_log["Counter"]."<br/>";
  }
}

$db = null;
?>
