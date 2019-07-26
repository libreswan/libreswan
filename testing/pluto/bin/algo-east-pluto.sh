#!/bin/sh

set -eu

. ../bin/algo-common.sh

echo check that the stack is ${responder_stack}
grep protostack=${responder_stack} /etc/ipsec.conf

# XXX: should add the right crypt
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-algo
ipsec auto --status
