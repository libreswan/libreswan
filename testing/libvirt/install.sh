#!/bin/sh -x

set -eu

# Assume this script is in testing/libvirt/ adjacent to testing/utils/
TESTING=$(dirname $(readlink -f $0))
TESTDIR=$(dirname $TESTING)
LIBRESWANSRCDIR=$(dirname $TESTDIR)

source ${LIBRESWANSRCDIR}/kvmsetup.sh

# backward commpatible; old kvmsetup.sh files modify LIBRESWASRCDIR
# and TESTDIR
TESTINGDIR=${TESTINGDIR:-${TESTDIR}}
SOURCEDIR=${SOURCEDIR:-${LIBRESWANSRCDIR}}

echo "TESTINGDIR=${TESTINGDIR}"
echo "SOURCEDIR=${SOURCEDIR}"
echo "POOLSPACE=${POOLSPACE}"
echo "OSTYPE=${OSTYPE}"
echo "OSMEDIA=${OSMEDIA}"

if [ -z "${POOLSPACE}" -o \
    -z "${OSTYPE}" -o \
    -z "${OSMEDIA}" -o \
    -z "${LIBRESWANSRCDIR}" ]; then
    echo "broken kvmsetup.sh, aborted"
    exit 42
fi

if touch /var/lib/libvirt/qemu/lswantest; then
    rm -f /var/lib/libvirt/qemu/lswantest
else
    echo "The qemu group needs write permissions in directory"
    echo "/var/lib/libvirt/qemu/. Ensure your user's main group is qemu,"
    echo "and chmod g+w /var/lib/libvirt/qemu"
    exit 43
fi

if [ ! -d "${POOLSPACE}" ]; then
    mkdir -p ${POOLSPACE}
    chmod a+x ${POOLSPACE}
fi

# Let's start
olddir=$(pwd)
cd ${TESTING}

echo "testing "${OSTYPE}"base.ks"

if [ ! -f "${OSTYPE}"base.ks ]; then
    echo "unknown distribution, no kickstart file found"
    exit 42
fi

# Create the virtual networks

(
    cd ${LIBRESWANSRCDIR}
    make install-kvm-networks \
	 'KVM_OS=${OSTYPE}' \
	 'KVM_POOLDIR=${POOLSPACE}' \
	 'KVM_SOURCEDIR=${SOURCEDIR}' \
	 'KVM_TESTINGDIR=${TESTINGDIR}'
)

echo "creating VM disk image"

base=${POOLSPACE}/swan"${OSTYPE}"base
if [ ! -f $base.qcow2 ]; then
    echo "Creating base ${OSTYPE} image using libvirt"

    # check for hardware VM instructions
    cpu="--hvm"
    grep vmx /proc/cpuinfo > /dev/null || cpu=""

    if test -r $base.img; then
	echo "$base.img exists, not creating"
    else
	echo "creating $base.img"
	# create the 8GB disk image ourselves - latest virt-install won't create it
	chmod ga+x ~ ${POOLSPACE}
	fallocate -l 8G $base.img
    fi
    # install base guest to obtain a file image that will be used as uml root
    # For static networking add kernel args parameters ip=.... etc
    # (network settings in kickstart are ignored by modern dracut)
    sudo virt-install --connect=qemu:///system \
	--network=network:swandefault,model=virtio \
	--initrd-inject=./"${OSTYPE}"base.ks \
	--extra-args="swanname=swan${OSTYPE}base ks=file:/${OSTYPE}base.ks \
	   console=tty0 console=ttyS0,115200" \
	--name=swan"${OSTYPE}"base \
	--disk path=$base.img \
	--ram 1024 \
	--vcpus=1 \
	--check-cpu \
	--accelerate \
	--location=${OSMEDIA} \
	--nographics \
	--noreboot \
	$cpu || exit $?

    # create many copies of this image using copy-on-write
    echo "converting $base.img to qcow2"
    sudo qemu-img convert -O qcow2 $base.img $base.qcow2
fi

for hostname in $(${TESTDIR}/utils/kvmhosts.sh); do
    # Use the the base disk to create VM disks
    rm -f ${POOLSPACE}/${hostname}.qcow2
    qemu-img create -F qcow2 -f qcow2 \
	-b $base.qcow2 ${POOLSPACE}/${hostname}.qcow2
    if [ -x /usr/sbin/restorecon ]; then
	sudo restorecon ${POOLSPACE}/${hostname}.qcow2
    fi

    # Create VM
    rm -f vm/${hostname}.converted
    cp vm/${hostname} vm/${hostname}.converted
    sed -i \
	-e "s:@@NAME@@:${hostname}:" \
	-e "s:@@TESTINGDIR@@:${TESTINGDIR}:" \
	-e "s:@@SOURCEDIR@@:${SOURCEDIR}:" \
	-e "s:@@POOLSPACE@@:${POOLSPACE}:" \
	-e "s:@@USER@@:$(id -u):" \
	-e "s:@@GROUP@@:$(id -g qemu):" \
	vm/${hostname}.converted
    sudo virsh define vm/${hostname}.converted
    rm -f vm/${hostname}.converted
    sudo virsh start ${hostname}
done

sudo virsh undefine swan"${OSTYPE}"base
cd ${olddir}

echo "done"

