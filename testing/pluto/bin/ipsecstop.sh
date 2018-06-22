: ==== cut ====
pidof pluto && ipsec stop
(../bin/check-for-core.sh | tee OUTPUT/`hostname`.core.txt | grep "CORE FOUND") || rm OUTPUT/`hostname`.core.txt
grep "leak:" tmp/pluto.log > OUTPUT/leakdetect.txt
: ==== tuc ====
