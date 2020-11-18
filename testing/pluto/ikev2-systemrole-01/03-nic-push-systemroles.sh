#!/bin/sh

# nic is used as the System Role provisioning host
#
# System Role code to pull data from inventory and create configs files to push to west/east
# Below is simple reference example of two files that would be pushed to /etc/ipsec.d on
# both host east and west
# 
# NOTE: the System Role should only touch files inside /etc/ipsec.d/ on east and west and
# leave /etc/ipsec.conf and /etc/ipsec.secrets as-is.
#
# /etc/ipsec.d/west-east.conf
# conn west-east
# 	left=192.1.2.45
# 	leftid=@west
# 	right=192.1.2.23
# 	rightid=@east
# 	auto=ondemand
# 	authby=secret
#
# /etc/ipsec.d/west-east.secrets
# @east @west : PSK "SuperSecretAndRandom"
