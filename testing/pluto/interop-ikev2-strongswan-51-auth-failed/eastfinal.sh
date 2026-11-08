grep "parsed INFORMATIONAL request.*N(AUTH_FAILED)" /tmp/charon.log | cut -d "]" -f 2-
