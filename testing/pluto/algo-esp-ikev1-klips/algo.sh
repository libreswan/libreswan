v=ikev1
for e in 3des aes; do
    for i in md5 sha1; do
	name=esp-${v}-klips-${e}-${i}
	echo +
	echo + ${name}
	echo +
	ipsec whack --name ${name} \
	      --${v}-allow \
	      --psk \
	      \
	      --id @west \
	      --host 192.1.2.45 \
	      --nexthop 192.1.2.23 \
	      --client 192.0.1.0/24 \
	      \
	      --to \
	      \
	      --id @east \
	      --host 192.1.2.23 \
	      --nexthop=192.1.2.45 \
	      --client 192.0.2.0/24 \
	      \
	      --esp ${e}-${i} \
	      --encrypt \
	      --pfs
	ipsec auto --up ${name}
	echo +
	../bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
	echo +
	ipsec auto --delete ${name}
	echo +
    done
done
