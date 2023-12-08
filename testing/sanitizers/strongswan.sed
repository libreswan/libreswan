# Strongswan sanitizer

/ strongswan status$/ b match-strongswan
/ strongswan status / b match-strongswan
/ strongswan statusall / b match-strongswan
/ strongswan up / b match-strongswan
/ strongswan down / b match-strongswan
/ swanctl / b match-strongswan
b end-strongswan

:match-strongswan

  # print and read next line
  n
  /^[a-z]* #/ b end-strongswan

:next-strongswan

  /^  worker threads: .*$/ {
  	   N
	   s/^.*\n//
	   b next-strongswan
  }

  /^  loaded plugins: .*$/ {
  	   N
	   s/^.*\n//
	   b next-strongswan
  }

  /generating QUICK_MODE request [0-9]* \[ HASH \]/ {
  	   N
	   s/^.*\n//
	   b next-strongswan
  }

  s/Starting strongSwan .* IPsec/Starting strongSwan X.X.X IPsec/
  s/Status of IKE charon daemon (strongSwan .*):$/Status of IKE charon daemon (strongSwan VERSION):/
  s/ uptime: [0-9]* second[s]*, since .*$/ uptime: XXX second, since YYY/
  s/ uptime: [0-9]* minute[s]*, since .*$/ uptime: XXX minute, since YYY/
  s/ malloc: sbrk [0-9]*, mmap [0-9]*, used [0-9]*, free [0-9]*$/ malloc sbrk XXXXXX,mmap X, used XXXXXX, free XXXXX/g
  s/ ESTABLISHED [0-9]* second[s]* ago/ ESTABLISHED XXX second ago/
  s/ SPIs: [0-9a-f]*_i [0-9a-f]*_o/ SPIs: SPISPI_i SPISPI_o/
  s/ CPIs: [0-9a-f]*_i [0-9a-f]*_o/ CPIs: CPI_i CPI_o/
  s/ SPIs: [0-9a-f]*_i\(\**\) [0-9a-f]*_r\(\**\)/ SPIs: SPISPI_i\1 SPISPI_r\2/

  s/ [0-9]* bytes_\([io]\),/ XX bytes_\1,/g
  s/ [0-9]* bytes_\([io]\) ([0-9X]*s ago),/ XXX bytes_\1 (XXs ago),/g
  s/ [0-9]* bytes_\([io]\) ([0-9]* pkts\?, [0-9X]*s ago),/ XXX bytes_\1 (XX pkts, XXs ago),/g
  s/ rekeying in [0-9X]* minutes/ rekeying in XX minutes/g

  s/([0-9]* bytes)/(XXX bytes)/g

  s/QUICK_MODE request [0-9]* /QUICK_MODE request 0123456789 /
  s/QUICK_MODE response [0-9]* /QUICK_MODE response 0123456789 /

  s/established with SPIs .* and /established with SPIs SPISPI_i SPISPI_o and /
  s/maximum IKE_SA lifetime [0-9]*s/maximum IKE_SA lifetime XXXs/
  s/reauthentication already scheduled in [0-9]*s/reauthentication already scheduled in XXXs/
  s/received AUTH_LIFETIME of [0-9]*s/received AUTH_LIFETIME of XXXXs/
  s/rekeying in [0-9]* minutes/rekeying in XX minutes/
  s/scheduling reauthentication in [0-9]*s/scheduling reauthentication in XXXs/
  s/scheduling rekeying in [0-9]*s/scheduling rekeying in XXXs/
  s/server requested EAP_MD5 authentication.*$/server requested EAP_MD5 authentication XXX/
  s/server requested EAP_TLS authentication.*$/server requested EAP_TLS authentication (id 0xXX)/

  s/Failed to connect to nic.testing.libreswan.org port.*$/Failed to connect to nic.testing.libreswan.org XXX/

  # strip out our own changing vendor id
  s/received unknown vendor ID: 40:48.*/received unknown vendor ID: LIBRESWAN/

b match-strongswan

:end-strongswan
