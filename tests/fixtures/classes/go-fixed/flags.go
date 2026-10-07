package main

import (
	"os"
	"strconv"
)

var debugEnabled, _ = strconv.ParseBool(os.Getenv("DEBUG_ENABLED"))
