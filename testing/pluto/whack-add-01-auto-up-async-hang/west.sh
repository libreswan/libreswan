/testing/guestbin/swan-prep

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival

# Try asynchronously; should immediately detach

ipsec -n start --asynchronous base
ipsec -n start --async base
ipsec -n start --bg base
ipsec -n add --auto=up --asynchronous base
ipsec start --asynchronous base
ipsec delete base

# try synchronously; should eventually detach

ipsec add --auto=up base
ipsec delete base
