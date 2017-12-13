# seccomp test for east should be empty
hostname | grep east > /dev/null && ausearch -ts recent -i -m SECCOMP
: ==== cut ====
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
