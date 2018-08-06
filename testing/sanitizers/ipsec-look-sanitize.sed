# match: ipsec look et.al.

/^ ipsec look/ b match
/^ .*ipsec-look.sh/ b match
b end

:match

  # print and read
  n
  /^[a-z]* #/ b end

  # fix the date/time
  s/^\([^ ]*\) ... ... *[0-9]* [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} GMT [0-9]\{4\}/\1 NOW/
  s/^\([^ ]*\) ... ... *[0-9]* [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} EST [0-9]\{4\}/\1 NOW/
  s/^\([^ ]*\) ... ... *[0-9]* [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} UTC [0-9]\{4\}/\1 NOW/
  s/^\([^ ]*\) ... ... *[0-9]* [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} EDT [0-9]\{4\}/\1 NOW/

  # tun0x1001@192.1.3.209 IPIP: ...addtime(4,0,0)...
  s/addtime(.*,.*,.*)//

  # 192.0.1.0/24 dev eth0  proto kernel  scope link  src 192.0.1.254
  s/\(eth[0-9]\)  proto kernel  scope link  src/\1 proto kernel scope link src/g

  # due to a kernel difference? Just ignore the error code in the routing table
  s/metric 1024 error -.*/metric 1024 error -XXXX/g

b match

:end
