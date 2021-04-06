# east should show required PPK is missing
hostname | grep east > /dev/null && grep "PPK_ID not found" /tmp/pluto.log
ipsec whack --shutdown
