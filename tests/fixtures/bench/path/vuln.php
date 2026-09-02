<?php
$name = $_GET['name'];
echo file_get_contents("/srv/files/" . $name);
