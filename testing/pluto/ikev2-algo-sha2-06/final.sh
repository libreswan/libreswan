# stop on east caused crash on west at some point in the past
hostname |grep west > /dev/null || ipsec stop
