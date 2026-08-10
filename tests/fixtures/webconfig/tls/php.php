<?php
function call($ch) {
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    return curl_exec($ch);
}
