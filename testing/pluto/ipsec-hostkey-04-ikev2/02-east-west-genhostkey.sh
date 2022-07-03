# US vs THEM
us=$(hostname | cut -d. -f1)
them=$(case $us in east ) echo west ;; west ) echo east ;; esac)
leftright=$(case $us in east ) echo right ;; west ) echo left ;; esac)
echo us=${us} them=${them} leftright=${leftright}

# generate the host key and save it
ckaid=$(ipsec newhostkey 2>&1 | grep "showhostkey" | sed "s/^.*ckaid //")
# sanitizing brought to you by id-sanitize.sed
ipsec showhostkey --${leftright} --ckaid "${ckaid}" > OUTPUT/$us.hostkey
