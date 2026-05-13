#!/bin/bash

set -eu

op=$1 ; shift
gw=$1 ; shift

name=$(basename ${gw})

run() {
    echo -n "$@"": "
    "$@"
}

case "${op}" in
    uninstall )
	if info=$(sudo virsh net-info ${name} 2>/dev/null) ; then
	    if [[ "${info}" =~ Active:' '*yes ]] ; then
		run sudo virsh net-destroy ${name}
	    fi
	    if [[ "${info}" =~ Persistent:' '*yes ]] ; then
		run sudo virsh net-undefine ${name}
	    fi
	fi
	rm -f ${gw}
	rm -f ${gw}.*
	;;
    install )
	address=$1 ; shift
	prefix=$1 ; shift
	dhcp_start=$1 ; shift
	dhcp_end=$1 ; shift
	cat <<EOF > ${gw}.xml
<network ipv6='no'>
  <name>${name}</name>
  <forward mode='nat'/>
  <bridge name='${name}' stp='on' delay='0'/>
  <domain name='${name}'/>
  <ip address='${address}' prefix='${prefix}'>
    <dhcp>
      <range start='${dhcp_start}' end='${dhcp_end}'/>
    </dhcp>
  </ip>
</network>
EOF
	sudo virsh net-define ${gw}.xml
	sudo virsh net-autostart ${name}
	sudo virsh net-start ${name}
	;;
esac
