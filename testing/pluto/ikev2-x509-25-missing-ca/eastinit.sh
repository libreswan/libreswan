/testing/guestbin/swan-prep --nokeys

# east, but without root
/testing/x509/import.sh real/mainca/east.end.p12

# Add a distracting CA; avoids NSS aborting for having no CA at all
# (?!?)
/testing/x509/import.sh real/otherca/othereast.all.p12

# check
ipsec certutil -L

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2-westnet-eastnet-x509-cr
echo "initdone"
