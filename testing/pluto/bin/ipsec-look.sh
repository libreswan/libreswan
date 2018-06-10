#!/bin/sh

# dump raw version of what ../../pluto/bin/ipsec-look.sh manges
echo ==== cut ====
echo "start raw xfrm state:"
ip -o xfrm policy
echo "end raw xfrm state:"
echo ==== tuc ====

exec ipsec look "$@"
