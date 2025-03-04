../../guestbin/prep.sh

ipsec initnss

# --efence-protect; prior to 5.3 it had required_argument, oops
ipsec pluto --efence-protect xxx --config /etc/ipsec.conf # <=5.2 expected this
ipsec whack --shutdown # not running
ipsec pluto --efence-protect     --config /etc/ipsec.conf # >=5.3
# wait to startup to finish; shutting down early causes leaks.
../../guestbin/wait-until-pluto-started
ipsec whack --shutdown

# leak-detective
ipsec pluto --leak-detective --config /etc/ipsec.conf
# wait to startup to finish; shutting down early causes leaks.
../../guestbin/wait-until-pluto-started
ipsec whack --shutdown
