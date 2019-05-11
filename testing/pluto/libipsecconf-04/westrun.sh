ipsec auto --add first
ipsec auto --add second
# conn second should inherit the conn %default values with 3des-md5
ipsec status |grep "algorithms:"
echo done
