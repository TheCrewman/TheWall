<?php

  $log_file = fopen("/home/pi/TheWall/logs/http_connections.log", "r");
  $log_content = fread($log_file, filesize("/home/pi/TheWall/logs/http_connections.log"));
  fclose($log_file);

  $http_conns = explode("\n", $log_content);

  for ($i = 0; $i < count($http_conns) - 1; $i++)
  {
    echo $http_conns[$i]."<br/>";
  }

  echo $http_conns[count($http_conns) - 1];
?>
