../../guestbin/prep.sh

# force the kernel to use fixed IDs

sysctl -w net.ipsecif.use_fixed_reqid=1
unit=1
reqid_ipv4=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit))
reqid_ipv6=$(($(sysctl -n net.ipsecif.reqid_base) + 2 * unit + 1))

ifconfig ipsec${unit} create
ifconfig ipsec${unit} -link2
ifconfig ipsec${unit} inet tunnel 198.18.1.15 198.18.1.12
ifconfig ipsec${unit} inet 198.18.15.15/24 198.18.12.12

ifconfig ipsec${unit}
ipsec _kernel policy
