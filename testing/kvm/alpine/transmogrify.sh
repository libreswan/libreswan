#!/bin/sh

set -xe ; exec < /dev/null

# update /etc/fstab with current /source and /testing

mkdir -p /source /testing
sed -e '/:/d' /etc/fstab > /tmp/fstab

cat <<EOF >> /tmp/fstab
@@GATEWAY@@:@@SOURCEDIR@@   /source         nfs     rw	0 0
@@GATEWAY@@:@@TESTINGDIR@@  /testing        nfs     rw	0 0
EOF

mv /tmp/fstab /etc/fstab
cat /etc/fstab

# chsh -s /bin/bash root
sed -i -e 's,root:/bin/.*,root:/bin/bash,' /etc/passwd

for f in /bench/testing/kvm/root/[a-z]* ; do
    cp -v ${f} /root/.$(basename $f)
done
