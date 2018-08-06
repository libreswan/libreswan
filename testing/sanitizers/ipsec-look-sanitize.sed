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

  # 192.0.1.0/24 dev eth0  proto kernel  scope link  src 192.0.1.254
  s/\(eth[0-9]\)  proto kernel  scope link  src/\1 proto kernel scope link src/g

  # due to a kernel difference? Just ignore the error code in the routing table
  s/metric 1024 error -.*/metric 1024 error -XXXX/g

  # the following was in the .pl sanitizer

  s/iv=0x[0-9a-f]\{32\}/iv=0xIVISFORRANDOM000IVISFORRANDOM000/;
  s/iv=0x[0-9a-f]\{16\}/iv=0xIVISFORRANDOM000/;

  s/jiffies=[0-9a-f]\{10\}/jiffies=0123456789/;

  s/addtime(.*,.*,.*)//;
  s/usetime(.*,.*,.*)//;
  s/bytes(.*)//;
  s/life(c,s,h)= //g;

  s/bit=\S*//g;
  s/idle=\S*//g;
  s/refcount=\S*//g;
  s/ref=\S*//g;
  s/seq=\S*//g;
  s/ratio=\S*//g;

b match

:end
