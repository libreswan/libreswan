# set 01-freebsdset-add-interface.sh

set# ../../guestbin/prep.sh
set# 
set# ifconfig ipsec1 create reqid 100
set# ifconfig ipsec1 inet tunnel 198.18.1.15 198.18.1.12
set# ifconfig ipsec1 inet 198.18.15.15/24 198.18.12.12
set# 
set# ifconfig ipsec1
set# ipsec _kernel state
set# ipsec _kernel policy

# rise 02-freebsdrise-add-interface.sh

rise# ../../guestbin/prep.sh
rise# 
rise# ifconfig ipsec1 create reqid 100
rise# ifconfig ipsec1 inet tunnel 198.18.1.12 198.18.1.15
rise# ifconfig ipsec1 inet 198.18.12.12/24 198.18.15.15
rise# 
rise# ifconfig ipsec1
rise# ipsec _kernel state
rise# ipsec _kernel policy

# set 03-freebsdset-ipsec-add.sh

set# ipsec start
set# ../../guestbin/wait-until-pluto-started
set# 
set# ipsec add rise-set

# rise 04-freebsdrise-ipsec-up.sh

rise# ipsec start
rise# ../../guestbin/wait-until-pluto-started
rise# 
rise# ipsec add rise-set
rise# ipsec up rise-set # sanitize-retransmits
rise# 
rise# sleep 10 # give fping some time

# set 05-freebsdset-ping.sh

set# ../../guestbin/ping-once.sh --up -I 198.18.15.15 198.18.12.12
set# 
set# ipsec _kernel state
set# ipsec _kernel policy

# rise 06-freebsdrise-ping.sh

rise# ../../guestbin/ping-once.sh --up -I 198.18.12.12 198.18.15.15
rise# 
rise# ipsec _kernel state
rise# ipsec _kernel policy

# final final.sh

final# ipsec delete rise-set
final# setkey -F
final# ifconfig ipsec1 destroy

