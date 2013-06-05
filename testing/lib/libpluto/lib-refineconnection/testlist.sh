export TZ=UTC

d() {
    expected=$1
    tee $expected.raw | sed -f canonicalize.sed | tee $expected.sane | diff -u - $expected | tee OUTPUT/$expected.diff
}

../refineconnection east.record	idlist.txt 2>&1 | d idlist-m-expected.txt
../refineconnection aggr.record	idlist.txt 2>&1 | d idlist-a-expected.txt
../refineconnection west-east-x509.record idlist.txt 2>&1  | d idlist-wex-expected.txt
