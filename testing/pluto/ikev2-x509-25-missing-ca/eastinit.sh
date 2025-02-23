/testing/guestbin/swan-prep --nokeys

# east, but without root
/testing/x509/import.sh real/mainca/east.end.p12
# Insert a different, broken, CAcert chain
# Avoids NSS aborting for having no CA at all (?!?)
/testing/x509/import.sh real/badca/badeast.all.p12
# Don't add CT to root bad cert; otherwise the message:
#    no Certificate Authority in NSS Certificate DB
# doesn't appear (but doesn't that contradict above?)
# # ipsec certutil -M -n badca -t CT,,

# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"
