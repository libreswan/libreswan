#!/bin/sh

klips_git=${1-/mara7/hifn/klips-ocf}
openswan_git=`pwd`
patchdir=$openswan_git/linux/patches

set -e

if [ ! -f $klips_git/README.openswan-2 ]
then
	echo klips_git '(arg1)' is not set right: $klips_git
	echo file $klips_git/README.openswan-2 is missing.
	exit 1
fi


if [ ! -f packaging/utils/kerngitpull.sh ]
then
	echo Please run this from the root of the openswan tree.
	exit 2
fi

# generate set of patches against last time we did this, and apply
# the patches to the linux/ subtree.
rm -rf $patchdir

cd $klips_git

mkdir -p $patchdir
git-format-patch -o $openswan_git/linux/patches openswan_klips

SIGNOFF=${SIGNOFF-"Michael Richardson <mcr@xelerance.com>"}
mkdir -p .dotest

cd $openswan_git/linux
for p in patches/0*.txt
do
    rm -rf .dotest && mkdir -p .dotest
    num_msgs=$(git-mailsplit "$p" .dotest) || exit 1

    set -- x .dotest/0*
    shift
    while case "$#" in 0) break;; esac
    do
	i="$1"
	git-mailinfo -k .dotest/msg .dotest/patch <$i >.dotest/info
	git-stripspace <.dotest/msg >.dotest/msg-clean
	sed -e 's|^\+\+\+ b/|+++ b/linux/|' -e 's|^--- a/|--- a/linux/|' <.dotest/patch >.dotest/patch-osw
	#cat .dotest/patch-osw
	(cd $openswan_git && git-applypatch linux/.dotest/msg-clean linux/.dotest/patch-osw linux/.dotest/info "$SIGNOFF" )
	read ans
	shift
    done
done

rm -rf .dotest

cd $klips_git
cg-switch openswan_klips
cg-update master
cg-switch master


