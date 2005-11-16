#!/bin/sh
/usr/bin/telnet localhost chargen | head -c 65536
