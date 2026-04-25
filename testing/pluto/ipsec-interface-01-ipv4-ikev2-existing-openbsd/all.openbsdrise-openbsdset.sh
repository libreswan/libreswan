# set 01-openbsdset-add-interface.sh

set# ../../guestbin/prep.sh
set# 
set# ifconfig sec1 create
set# ifconfig sec1 inet 198.18.15.15/24 198.18.12.12
set# ifconfig sec1 up
set# 
set# ifconfig sec1
set# ipsec _kernel state
set# ipsec _kernel policy

# rise 02-openbsdrise-add-interface.sh

rise# ../../guestbin/prep.sh
rise# 
rise# ifconfig sec1 create
rise# ifconfig sec1 inet 198.18.12.12/24 198.18.15.15
rise# ifconfig sec1 up
rise# 
rise# ifconfig sec1
rise# ipsec _kernel state
rise# ipsec _kernel policy

# set 03-openbsdset-ipsec-add.sh

set# ipsec start
set# ../../guestbin/wait-until-pluto-started
set# 
set# ipsec add rise-set

# rise 04-openbsdrise-ipsec-up.sh

rise# ipsec start
rise# ../../guestbin/wait-until-pluto-started
rise# 
rise# ipsec add rise-set
rise# ipsec up rise-set # sanitize-retransmits

# set 05-openbsdset-ping.sh

set# ../../guestbin/ping-once.sh --up -I 198.18.15.15 198.18.12.12
set# 
set# ipsec _kernel state
set# ipsec _kernel policy

# rise 06-openbsdrise-ping.sh

rise# ../../guestbin/ping-once.sh --up -I 198.18.12.12 198.18.15.15
rise# 
rise# ipsec _kernel state
rise# ipsec _kernel policy

# final final.sh

final# ifconfig sec1 destroy

