#!/bin/sh

# This is the configuration file that helps setup for
# a kernel pool for UML compilation w/FreeSWAN.
#
# Copy this file to the top of your FreeSWAN source directory as
# umlsetup.sh, edit that copy, and populate the paths.


# space for everything:
# Just a shorthand for the following definitions.
# Can be eliminated if available space is fragmented.
UMLPREFIX=/home/build/uml-testing

REGRESSRESULTS=$UMLPREFIX/results

# set this to someplace with at least 100Mb free.
POOLSPACE=$UMLPREFIX/umlbuild

# if you are using a 2.6 kernel,
KERNVER=26

# Set this to original kernel source.
# It will not be modified.
# Could be native build:
#KERNPOOL=/usr/src/linux
#
# or something you downloaded.
KERNPOOL=/home/build/uml-files/linux-2.6.38

# if you have a kernel that already has the NAT-T patch applies, then
# set this to false.
NATTPATCH=false

<<<<<<< HEAD
=======
# if you want a kernel that supports the BTNS IPsec API
#   see draft-ietf-btns-capi-xx.txt
# this requires your kernel to be rebuilt.
SAREFPATCH=false

# if you also have a copy of the L2TP IPsec API patch, you can
# set this to true as well
NGUDPPATCH=false

>>>>>>> aa1127c8a40947f6830d54a057b4ae116019484a
# NONINTPATCH is a patch that comes from Redhat kernels. It permits
# "make oldconfig" to complete without interacting with the user.
# I think that 2.6. kernels have this. This patch is optional, if you
# do not want it, then set it to "none".  The purpose of the patch is
# make scripts/cronjobs not hang if you run with too new a kernel.
NONINTPATCH=none

# For make check's kernel patch tests, virgin kernel sources are needed
# They will not be modified.
#KERNEL_LINUS2_0_SRC=
#KERNEL_LINUS2_2_SRC=
KERNEL_LINUS2_4_SRC=$KERNPOOL

# set this to the UML tar file, gotten from, e.g.
#     http://ftp.nl.linux.org/uml/uml-patch-2.4.18-53.bz2
#
<<<<<<< HEAD
UMLPATCH=none
=======
#UMLPATCH=$UMLPREFIX/download/uml-patch-2.4.19-47.bz2
>>>>>>> aa1127c8a40947f6830d54a057b4ae116019484a

# set BASICROOT this to an unpacked copy of the root file system you
# want to use.
#
# a small-ish one is at:
#     http://www.sandelman.ottawa.on.ca/freeswan/uml/
#
# umlfreeroot-5.1.tar.gz  is 17Mb, unpacks to around 50Mb.
#
# umlfreesharemini.tar.gz is 3Mb, unpacks to around 8Mb.
# umlfreeshareall.tar.gz is 6Mb, unpacks to around 26Mb.
#
# I did
#   mkdir -p $UMLPREFIX/basic-root
#   cd $UMLPREFIX/basic-root
#   nftp -o - http://www.sandelman.ottawa.on.ca/freeswan/uml/umlfreeroot-12.0.tar.gz | tar xzvf -
#  (or ncftp, or whatever your favorite program is)
#
# There is an advantage to having this on the same partition as
# $POOLSPACE, as hard links can be used.
#
BASICROOT=/home/build/uml-files/root-36
BASICROOT=/home/build/uml-files/root-precise-i386

INITRD_FILES='initrd-precise-i686.list'

# the mini /usr/share has Canada zoneinfo and "en" locale only.
# the all one has everything from the original UML debian root.
# I run debian, so I can just use my native /usr/share!
SHAREDIR=/usr/share

# note that "nic" and "sec" are the same host in different configurations
REGULARHOSTS='sunrise sunset nic carrot beet sec pole'
LIBRESWANHOSTS='east west japan road north'

# tell system location of special tcpdump, if any
export TCPDUMP="/usr/sbin/tcpdump"

# we always use OBJ directories for UML builds.
USE_OBJDIR=true export USE_OBJDIR

#
# OTHER THINGS YOU CAN SET, but problem shouldn't.
#

# UML_xxx_KERNEL
#  If set, then the kernel for UML named "xxx" (lower case) will be set
#  to this value rather than to UMLPOOL/swanXX/linux. This permits you to
#  easily test against other kernels.
#
#UML_east_KERNEL=/path/to/kernel
#
# If you set UML_plain26_KERNEL or UML_swan26_KERNEL to a value, then that
# kernel will be used instead of building a local kernel. If you are doing
# only user-space work, you can avoid all kernel builds this way.
#

# UML_extra_DIRS
#
#UML_extra_DIRS="/mara2/sandboxes/l2tpd /mara1/git/iproute2 /mara7/tcpdump/tcpdump"
# this will cause the make uml system to go into each directory and run:
#   make DESTDIR=$UMLPOOL/host/root install
#
# This permits you to include additional software in the UML root easily.



# comment this out to signify that you've customized this script
#echo "please create a umlsetup.sh" ; exit 99
