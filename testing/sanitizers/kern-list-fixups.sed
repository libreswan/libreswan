/tracing thread pid = \(.*\)/d
s/spawn \(.*\) single/spawn PATH single/
s/Program invoked with \(.*\)\/start.sh/Program invoked with PATH\/start.sh/
s/Starting UML \(.*\)\/start.*sh/Starting UML PATH\/start.sh/
s/Kernel command line: .*/Kernel command line:/
/mconsole .*initialized on .*/d
s/Calculating module dependencies... .*/Calculating module dependancies/
s/Loading modules: .*/Loading modules: LIST/
/modprobe: /d
s/Calibrating delay loop... .*/Calibrating delay loop... XXXX bogomips/
s/Linux version .*/Linux version XXXX/
/hostfs on /d
s/devfs: v.* Richard Gooch (rgooch@atnf.csiro.au)/devfs: VERSION Richard Gooch (rgooch@atnf.csiro.au)/
s/devfs: boot_options: .*/devfs: boot_options Q/
s/block: .*/block: slots and queues/
s,/tmp/.*\.d/private,/tmp/UML.d/private,
s,/tmp/.*\.d/admin,/tmp/UML.d/admin,
s,/tmp/.*\.d/public,/tmp/UML.d/public,
/INIT: can't open(.etc.ioctl.save, O_WRONLY): Permission denied/d
/VFS: Mounted root (root.hostfs filesystem) readonly./d
s/^VFS: Disk.*/VFS: Diskquotas version dquot_6.4.0 initialized/
/ipsec_setup: Unknown HZ value! .* Assume 100./d
/^Checking for/d
/^Checking that/d
/^Memory: .* available/d
/^Netdevice .* : daemon backend.*/d
/^daemon_setup : Ignoring data socket specification/d
/^unable to open /d
/^nbd: module cleaned up./d
/^.*ip_conntrack .*/d
/^.*nf_conntrack .*/d
/^.*ip_tables: .*/d
/^.*ip6_tables: .*/d
/echo Starting loading module/,/^Finished loading module.*/d
/^none on \/testing type hostfs .*/d
/^none on \/usr\/src type hostfs .*/d
/^zone(.): .* pages./d
/^Initializing stdio console driver/d
/^cp: .etc.nologin: No such file or directory/d
/Libreswan KLIPS IPsec stack version: .*/d
/Kernel logging (proc) stopped/d
/Kernel log daemon terminating/d
s/\(Dentry\).\(cache hash table entries:\).*/\1-\2 NUMBERS/
s/\(Inode\).\(cache hash table entries:\).*/\1-\2 NUMBERS/
s/\(Mount.cache hash table entries:\).*/Mount-cache hash table entries: NUMBERS/
s/\(Buffer.cache hash table entries:\).*/Buffer-cache hash table entries: NUMBERS/
s/\(Page-cache hash table entries:\).*/\1 NUMBERS/
/block: slots and queues/d
/RAMDISK driver initialized: 16 RAM disks of 4096K size 1024 blocksize/d
s/\(PPP generic driver version\).*/\1 VERSION/
s/\(Universal TUN\/TAP device driver\).*/\1 VERSION/
/arp_tables: /d
/^Checking whether the host supports skas mode/d
/^blkmtd: error, missing `device' name/d
/^Initializing software serial port version/d
s/TCP: Hash tables configured (established .* bind .*)/TCP: Hash tables configured (established 2048 bind 2048)/
/Configured mcast device: .*/d
/Netdevice 2/d
/VFS: Mounted root /d
/blkmtd: .*/d
/ipt_recent /d
/klips_info:pfkey_cleanup: shutting down PF_KEY domain sockets./d
/klips_info:cleanup_module: ipsec module unloaded./d
/klips_info:ipsec_alg_init: KLIPS alg v=0.8.1-0.*/d
/klips_info:ipsec_alg_init: calling ipsec_alg_static_init.*/d
/ipsec_aes_init(alg_type=15 alg_id=12 name=aes): ret=0/d
/ipsec_aes_init(alg_type=14 alg_id=9 name=aes_mac): ret=0/d
/aio_thread failed to initialize context/d
/2.6 AIO not supported/d
/Disabling 2.6 AIO in tt mode/d
/none on \/usr\/local/d
/none on \/var\/tmp/d
/^$/d
/INIT: Switching to runlevel: 0/d
/INIT: Sending processes the TERM signal/d
/Failed to open 'root_fs'/d
s/none on \/usr\/obj type hostfs (ro,.*)/none on \/usr\/obj type hostfs (ro, PATH)/
/.*\/dev\/console$/d
/.*\/dev\/console.$/d
/^MOUNTING .*/d
/^.*padlock_sha: VIA PadLock Hash Engine not detected\.*$/d
/^.*AVX instructions are not detected.*$/d
/^.*AVX or AES-NI instructions are not detected.*$/d
/^.*Neither AVX nor SSSE3 is available.*$/d
/^.*sha1_ssse3: Neither AVX nor AVX2 nor SSSE3 is available\/usable\.$/d
/^.*sha512_ssse3: Using AVX2 optimized SHA.*$/d
/^.*sha256_ssse3: Using AVX2 optimized SHA-256.*$/d
/^.*ipsec: module verification failed.*$/d
/^.*ip6_tables: (C) 2000-2006 Netfilter Core Team$/d
/^.*NET: Registered protocol family .*$/d
/^.*NET: Unregistered protocol family 15$/d
/^.*IPv4 over IPsec tunneling driver.*$/d
/^.*PPP generic driver version.*$/d
/^.*PPP BSD Compression module registered$/d
/^.*PPP Deflate Compression module registered$/d
/^.*l2tp_core: L2TP core driver, V.*$/d
/^.*l2tp_netlink: L2TP netlink interface/d
/^.*l2tp_ppp: PPPoL2TP kernel driver, V.*$/d
/^.*PCLMULQDQ-NI instructions are not detected.*$/d
/^Warning: found NETKEY\/XFRM stack loaded.*$/d
/.*IPv4 over IPSec tunneling driver$/Id
/^.*random: nonblocking pool is initialized$/d
/^.* alg: No test for .*$/d
/^.*bytes leftover after parsing attributes in process.*$/d
s/TTL=63 ID=[0-9]* PROTO/TTL=63 ID=XXXXX PROTO/
/^.*CPU feature 'AVX registers' is not supported.*$/d
