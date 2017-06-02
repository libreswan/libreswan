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

cd ${directory}

# Will need to wait until this background process has printed
# "starting" on stdout.
python3 -m http.server ${port} "$@" &
echo $! > simple-http-server.pid

# Wait for the server to start by probing it using netcat.
i=0
while true ; do
    if ncat 127.0.0.1 ${port} < /dev/null 2>/dev/null ; then
	exit 0
    fi
    i=$((i + 1))
    test $i -lt 5 || break
    sleep 1
done

echo Timeout waiting for HTTP server on ${port} to start
exit 1
