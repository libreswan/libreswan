/testing/guestbin/swan-prep
# build install se module
../../guestbin/semodule.sh ipsecspd.te
setsebool domain_can_mmap_files=1
setsebool nis_enabled=1
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
