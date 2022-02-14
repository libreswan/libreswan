/testing/guestbin/swan-prep
# build install se module
../../guestbin/semodule.sh ipsecspd-full-perm.te
setsebool domain_can_mmap_files=1
setsebool nis_enabled=1
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
runcon -t netutils_t ipsec getpeercon_server -d 4300
echo "initdone"
