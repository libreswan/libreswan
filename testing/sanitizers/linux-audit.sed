s/audit([^ ]*)/audit(XXX)/
s/pid=[0-9]* /pid=PID /
s/auid=[0-9]* /auid=AUID /
s/ses=[0-9]* /ses=SES /
s/old=[0-9]* /old=XXX /
s/spi=[0-9]*(0x[0-9a-f]*) /spi=DEC(HEX) /g
s/ipcomp=[0-9]*(0x[0-9a-f]*) /spi=DEC(HEX) /g
