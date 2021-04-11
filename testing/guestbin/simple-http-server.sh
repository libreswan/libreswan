#!/bin/sh

if test $# -lt 2 ; then
    cat <<EOF > /dev/stderr

Usage:

    $0 <directory> <port> [ <http-arg> ... ]

start a background python3 http.server in <directory> listening to
<port>

EOF

    exit 1
fi

directory=$1 ; shift
port=$1 ; shift
logfile=simple-http-server.log
pidfile=simple-http-server.pid

cd ${directory}

# Start the server in the background.
#
# Force un-buffered output so that the start-up message is immediately
# written to the log file (without it the log file remains empty).

python3 -u -m http.server ${port} "$@" > ${logfile} 2>&1 &
echo $! > ${pidfile}

# Wait for the server to start.  Check for both the "Serving ..." log
# line and an open port.

i=0
while true ; do
    if test -s ${logfile} && ncat 127.0.0.1 ${port} < /dev/null 2>/dev/null ; then
	# Strip off f28's extra text:
	# f22: Serving HTTP on 0.0.0.0 port 80 ...
	# f28: Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
	sed -e 's; (http://[^)]*);;' simple-http-server.log
	exit 0
    fi
    i=$((i + 1))
    test $i -lt 5 || break
    sleep 1
done

echo Timeout waiting for HTTP server on ${port} to start
cat ${logfile}
exit 1
