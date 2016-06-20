/testing/guestbin/swan-prep
( cd /source/testing/lib/libswan; rm -f algparse enumcheck; cd -)
( cd /source/testing/lib/libswan; make; cd -)
# diffs should be empty
cat /source/testing/lib/libswan/lib-algparse/OUTPUT/algparse.output.diff
cat /source/testing/lib/libswan/lib-enumcheck/OUTPUT/enumcheck.output.diff
echo "initdone"
