#s,\(TTL=[0-9]* ID=\)[0-9]* \(PROTO=ICMP TYPE=0 CODE=0 ID=\)[0-9]* \(SEQ=[0-9]*\),\1000 \2000 \3
s,hashsize=\([0-9]*\),hashlen=\1\, trunclen=0,
