<?php
$db = new PDO("sqlite:/home/pi/TheWall/logs/db/http_connections.db");

$all_logs = $db->query("SELECT * FROM logs");
foreach ($all_logs as $single_log)
{
  if (($single_log["Source_hostname"] != "") && ($single_log["Destination_hostname"] != ""))
  {
    echo "[".$single_log["Date"]." ".$single_log["Time"]."] ".$single_log["Source_IP"]." (".$single_log["Source_hostname"].") --> ".$single_log["Destination_IP"]." (".$single_log["Destination_hostname"].")<br/>";
  }
  else if (($single_log["Source_hostname"] != "") && ($single_log["Destination_hostname"] == ""))
  {
    echo "[".$single_log["Date"]." ".$single_log["Time"]."] ".$single_log["Source_IP"]." (".$single_log["Source_hostname"].") --> ".$single_log["Destination_IP"]."<br/>";
  }
  else if (($single_log["Source_hostname"] == "") && ($single_log["Destination_hostname"] != ""))
  {
    echo "[".$single_log["Date"]." ".$single_log["Time"]."] ".$single_log["Source_IP"]." --> ".$single_log["Destination_IP"]." (".$single_log["Destination_hostname"].")<br/>";
  }
  else if (($single_log["Source_hostname"] == "") && ($single_log["Destination_hostname"] == ""))
  {
    echo "[".$single_log["Date"]." ".$single_log["Time"]."] ".$single_log["Source_IP"]." --> ".$single_log["Destination_IP"]."<br/>";
  }
}

$db = null;
?>
