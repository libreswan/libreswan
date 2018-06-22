
Instructions for running Opportunistic IPsec with Letsencrypt

# Install libreswan 3.19oe2 via rpm or srpm listed here
# Install the Letsencrypt related certificates:
mkdir letsencrypt
cd letsencrypt
wget https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem
wget https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem
wget https://letsencrypt.org/certs/isrgrootx1.pem
# based on https://www.identrust.com/certificates/trustid/root-download-x3.html
wget https://nohats.ca/LE/identrust-x3.pem
#
certutil -A -i lets-encrypt-x3-cross-signed.pem -n lets-encrypt-x3 -t CT,, -d sql:/etc/ipsec.d
certutil -A -i lets-encrypt-x4-cross-signed.pem -n lets-encrypt-x4 -t CT,, -d sql:/etc/ipsec.d
certutil -A -i isrgrootx1.pem -n isrgrootx1 -t CT,, -d sql:/etc/ipsec.d
certutil -A -i identrust-x3.pem -n identrust-x3 -t CT,, -d sql:/etc/ipsec.d
#
# configure libreswan for letsencrypt
cd /etc/ipsec.d
wget https://nohats.ca/LE/oe-letsencrypt-client.conf
echo "193.110.157.131/32" >> /etc/ipsec.d/policies/private-or-clear
# if you want to enable it for all remote servers, put 0.0.0.0/0 in private-or-clear
# restart libreswan
ipsec restart
# [wait 2 seconds]
ping letsencrypt.libreswan.org
ipsec whack --trafficstatus
# check if it was encrypting using
# tcpdump -n host letsencrypt.libreswan.org

