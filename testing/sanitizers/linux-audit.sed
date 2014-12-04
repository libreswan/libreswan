s/audit([^ ]*)/audit(XXX)/
s/pid=[0123456789]* /pid=PID /
s/auid=[0123456789]* /auid=AUID /
s/ses=[0123456789]* /ses=SES /
s/old=[0123456789]* /old=XXX /
# libreswan audit msgs
s/inSPI=[0123456789]*(0x[0123456789abcdef]*) outSPI=[0123456789]*(0x[0123456789abcdef]*) /inSPI=DEC(HEX) outSPI(DEC(HEX) /
s/inIPCOMP=[0123456789]*(0x[0123456789abcdef]*) outIPCOMP=[0123456789]*(0x[0123456789abcdef]*) /inSPI=DEC(HEX) outSPI(DEC(HEX) /
# kernel audit msgs
s/spi=[0123456789]*(0x[0123456789abcdef]*) /spi=DEC(HEX) /
