/^\(.*\)# ipsec look/N
s/^\(.*# ipsec look\n.*\) ... ... .. ..:..:.. GMT ..../\1 NOW/
s/^\(.*# ipsec look\n.*\) ... ... .. ..:..:.. EST ..../\1 NOW/
s/^\(.*# ipsec look\n.*\) ... ... .. ..:..:.. UTC ..../\1 NOW/
s/addtime(.*,.*,.*)//

