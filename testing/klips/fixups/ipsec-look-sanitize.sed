/^\(.*\)# ipsec look/N
s/^\(.*# ipsec look\n.*\) ... ... .. ..:..:.. GMT ..../\1 NOW/
s/^\(.*# ipsec look\n.*\) ... ... .. ..:..:.. EST ..../\1 NOW/
s/^\(.*# ipsec look\n.*\) ... ... .. ..:..:.. UTC ..../\1 NOW/
s/addtime(.*,.*,.*)//
# these lines obsolete part of ipsec-look-esp-sanitize.pl which seems broken
s/esp\.[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]@/esp.ESPSPIi@/g
s/ah\.[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]@/ah.AHSPIi@/g
s/comp\.[a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9][a-z0-9]@/comp.COMPSPIi@/g
