/^\(.*\)# ipsec look/N
s/^\([^ ]*\) ... ... *[0-9]* [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} GMT [0-9]\{4\}/\1 NOW/
s/^\([^ ]*\) ... ... *[0-9]* [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} EST [0-9]\{4\}/\1 NOW/
s/^\([^ ]*\) ... ... *[0-9]* [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} UTC [0-9]\{4\}/\1 NOW/
s/^\([^ ]*\) ... ... *[0-9]* [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} EDT [0-9]\{4\}/\1 NOW/
s/addtime(.*,.*,.*)//
# these lines obsolete part of ipsec-look-esp-sanitize.pl which seems broken
# allow for the dropping of leading zero's
s/esp\.[a-z0-9]\{1,8\}@/esp.ESPSPIi@/g
s/ah\.[a-z0-9]\{1,8\}@/ah.AHSPIi@/g
s/comp\.[a-z0-9]\{1,8\}@/comp.COMPSPIi@/g
