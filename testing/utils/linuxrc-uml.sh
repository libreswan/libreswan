#!/bin/sh

PATH="/sbin:/bin"


# defaults
tmpfs_size="10M"
udev_root="/root/dev"

# mount a tmpfs over /dev, if somebody did not already do it
mount_tmpfs() {
  if grep -E -q "^[^[:space:]]+ /dev tmpfs" /proc/mounts; then
    return 0
  fi

  # /dev/.static/dev/ is used by MAKEDEV to access the real /dev/ directory.
  # /etc/udev/ is recycled as a temporary mount point because it's the only
  # directory which is guaranteed to be available.
  mount -n --bind /dev /devt

  echo -n "Mounting a tmpfs over /dev..."
  if ! mount -n -o size=$tmpfs_size,mode=0755 -t tmpfs tmpfs /root/dev; then
    echo " FAILED!"
    echo "FATAL: udev requires tmpfs support, not started."
    umount /etc/udev
    exit 1
  fi

  # using ln to test if /dev works, because touch is in /usr/bin/
  if ln -s test /root/dev/test-file; then
    rm /root/dev/test-file
    echo "done."
  else
    echo " FAILED!"
    echo "FATAL: udev requires tmpfs support, not started."
    umount /devt
    umount /dev
    exit 1
  fi

  mkdir -p /root/dev/.static/dev
  chmod 700 /root/dev/.static/
  mount -n --move /devt /root/dev/.static/dev
}

# I hate this hack.  -- Md
make_extra_nodes() {
  [ -e /root/etc/udev/links.conf ] || return 0
  grep '^[^#]' /root/etc/udev/links.conf | \
  while read type name arg1; do
    [ "$type" -a "$name" -a ! -e "/root/dev/$name" -a ! -L "/root/dev/$name" ] ||continue
    case "$type" in
      L) ln -s $arg1 /root/dev/$name ;;
      D) mkdir -p /root/dev/$name ;;
      M) mknod --mode=600 /root/dev/$name $arg1 ;;
      *) echo "links.conf: unparseable line ($type $name $arg1)" ;;
    esac
  done
  [ -c /root/dev/console ] || mknod /root/dev/console c 5 1
  [ -c /root/dev/null ] || mknod /root/dev/null c 1 3
}

##############################################################################

mount -n -t proc none /proc
if grep SHELL /proc/cmdline; then echo STARTING SHELL - exit to continue; /bin/sh; fi

for v in $(cat /proc/cmdline)
do
	case $v in
	umlroot=*) hostfsroot=${v#umlroot=};;
	esac
done

echo MOUNTING $hostfsroot for UML testing root.
mount -n -o $hostfsroot -t hostfs none /root

echo 256 >/proc/sys/kernel/real-root-dev

if ! grep -q '[[:space:]]tmpfs$' /proc/filesystems; then
  echo "udev requires tmpfs support, not started."
  exit 0
fi

##############################################################################

udev_root=${udev_root%/}

mount_tmpfs
echo -n "Creating initial device nodes..."
make_extra_nodes
echo "done."

echo Invoked with Arguments: $*

cd /root
pivot_root . initrd 
cd /
exec /sbin/init $*

