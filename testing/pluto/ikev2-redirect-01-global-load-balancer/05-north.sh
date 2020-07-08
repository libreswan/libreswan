ipsec auto --add north-east
ipsec auto --up north-east
echo "2. north connection add+up done"
ipsec auto --delete north-east
echo "2. north connection delete done"
