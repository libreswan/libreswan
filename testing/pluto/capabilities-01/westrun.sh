netcap | sed -n -e 's/[ \t][ \t]*/ /g' -e 's/^.*pluto/pluto/p' | sort
echo done
