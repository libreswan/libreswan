# to avoid shutdown logs confusing things, hard kill pluto
kill -9 `cat /run/pluto/pluto.pid`
