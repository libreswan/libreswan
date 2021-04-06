certutil -L -d sql:/etc/ipsec.d
# catch any cert chain specific leaks
ipsec whack --shutdown
