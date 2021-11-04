# taken straight from the socat examples
port=$1 ; shift
ipv=4

socat -T 1 -d -${ipv} TCP-LISTEN:${port},reuseaddr,fork,crlf \
      SYSTEM:"echo -e \"\\\"HTTP/1.0 200 OK\\\nDocumentType: text/html\\\n\\\n<html>date: \$\(date\)<br>server:\$SOCAT_SOCKADDR:\$SOCAT_SOCKPORT<br>client: \$SOCAT_PEERADDR:\$SOCAT_PEERPORT\\\n<pre>\\\"\"; cat; echo -e \"\\\"\\\n</pre></html>\\\"\"" \
      > OUTPUT/$(hostname).httpd.${ipv}.${port}.log 2>&1 &
