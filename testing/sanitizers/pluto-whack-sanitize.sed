# {ESP=>0xf38023da <0xf7e45c43 ...}
# {AH=>0xf38023da <0xf7e45c43 ...}
# {ESPinUDP/ESN=>0xf38023da <0xf7e45c43 ...}
s/{\([A-Z]*\)\([^=]*\)=>0x[a-f0-9]* <0x[a-f0-9]*\(.*\)}/{\1\2=>0x\1\1 <0x\1\1\3}/

# {... IPCOMP=... }
s/{\(.*\) IPCOMP=>0x[a-f0-9]* <0x[a-f0-9]*\(.*\)}/{\1 IPCOMP=>0xCPI <0xCPI\2}/

# IKEv2: {ESP <0xESPESP}
s/{\([A-Z]*\)\([a-z]*[A-Z]*\) <0x[a-f0-9]*\(.*\)}/{\1\2 <0x\1\1\3}/
s/{\(.* IPCOMP\) <0x[a-f0-9]*\(.*\)}/{\1 <0xCPI\2}/

# Generated RSA keys have some fuzz
s/ \([0-9]\)[0-9][0-9][0-9]-bit RSA/ \1nnn-bit RSA/
s/ \([0-9]\)[0-9][0-9]-bit RSA/ \1nn-bit RSA/

/msgid[:=]00000000/! { s,msgid\([:=]\)[0-9a-z]*,msgid\1MSGID, ; }

s,; \([a-z0-9A-Z_]\+\) in [0-9]\+s,; \1 in XXs,g
s, remaining life [0-9][0-9\.]*s, remaining life XXs,

s/add_time=[0-9]*,/add_time=1234567890,/
s/, age=[^,]*,/, age=XXX,/
s/SN: 0x[a-f0-9]*/SN: 0xXX/

# Hack: real fix is to cleanup the delete log line and use str_datetime()
s/ aged [0-9]*\.[0-9]*s / /

/ERROR: asynchronous network error report/d
