#!/bin/sh

OS_CVS=anoncvs@anoncvs.openswan.org:/cvs/openswan
OS_FTP=$USER@localhost:/tmp
GNUPGHOME=/mnt/build/openswan-2
export GNUPGHOME OS_CVS OS_FTP


echo "Checking out CVS ..."
rm -rf openswan-$1 > /dev/null
cvs -z9 -d $OS_CVS co openswan-2

mv openswan-2 openswan-$1
cd openswan-$1

echo "Fixing Makefile.inc..."
cat Makefile.inc | sed s/^USE_LWRES.*/USE_LWRES?=false/ | sed s/^USE_OE.*/USE_OE?=false/ > Makefile.inc2 && mv Makefile.inc2 Makefile.inc


echo "I am setting the Version info..."
cat Makefile.ver | sed s/2.CVSHEAD/$1/ > Makefile.ver2 && mv Makefile.ver2 Makefile.ver
cat packaging/redhat/openswan.26spec | sed s/2.CVSHEAD/$1/ > n && mv n packaging/redhat/openswan.26spec
cat packaging/redhat/openswan.spec | sed s/2.CVSHEAD/$1/ > n && mv n packaging/redhat/openswan.spec
cat packaging/suse/openswan.26spec | sed s/2.CVSHEAD/$1/ > n && mv n packaging/suse/openswan.26spec
echo "If there were any errors above, abort now... [2 second pause]"
sleep 2


# TAG CVS
echo "Tagging CVS..."
TAG=`echo $1 | sed s/\\\./_/g`
cvs tag v$TAG

echo "Removing CVS bits (CVS dirs, .cvsignore files, etc...)"
# Clean up CVS remnants
find ./ -name CVS | xargs rm -rf
find ./ -name .cvsignore | xargs rm -rf
cd  ..
echo "Creating & Signing Package..."
tar -czf openswan-$1.tar.gz openswan-$1
echo "Building patches..."
cd openswan-$1
make kernelpatch2.4 > ../openswan-$1.kernel-2.4-klips.patch
make kernelpatch2.6 > ../openswan-$1.kernel-2.6-klips.patch
make nattpatch2.4 > ../openswan-$1.kernel-2.4-natt.patch
make nattpatch2.6 > ../openswan-$1.kernel-2.6-natt.patch
cd  ..
# Compress patches
gzip openswan-$1.kernel-2.4-klips.patch
gzip openswan-$1.kernel-2.4-natt.patch
gzip openswan-$1.kernel-2.6-klips.patch
gzip openswan-$1.kernel-2.6-natt.patch
# Sign binaries
gpg -sba openswan-$1.tar.gz 
gpg -sba openswan-$1.kernel-2.4-klips.patch.gz
gpg -sba openswan-$1.kernel-2.4-natt.patch.gz
gpg -sba openswan-$1.kernel-2.6-klips.patch.gz
gpg -sba openswan-$1.kernel-2.6-natt.patch.gz
chmod 644 openswan-$1*.asc

echo "Uploading to ftp/www sites..."
scp openswan-$1.*.gz* $OS_FTP
scp openswan-$1/CHANGES $OS_FTP

# Move to old/ since we're done.
mv openswan-$1* old/ 
echo "Releasing Process Done"
