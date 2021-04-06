# Authentication should be AUTH_NULL
hostname | grep nic > /dev/null || grep authenticated /tmp/pluto.log
