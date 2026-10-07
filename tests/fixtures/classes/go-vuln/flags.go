package main

import "os"

var debugEnabled = os.Getenv("DEBUG_ENABLED") != ""
