# This depends on XFRM markers inserted by "ipsec look"
/^XFRM state:/,/XFRM done/s/sport [0-9]* /sport SPORT /g
