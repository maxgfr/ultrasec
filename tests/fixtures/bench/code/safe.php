<?php
$op = $_GET['op'];
$handlers = ['sum' => 'handleSum', 'avg' => 'handleAvg'];
// A dispatch table: the input selects a name, it is never compiled.
$fn = $handlers[$op] ?? 'handleSum';
http_response_code(200);
