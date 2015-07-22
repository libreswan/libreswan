#!/bin/sh

# This script allocates a number of SPIs, then deallocates them in a
# different order. It is driven by an input file which contains some
# generated SPI data.

def_enckey=0x4043434545464649494a4a4c4c4f4f515152525454575758
def_authkey=0x87658765876587658765876587658765

# input file is in the format:
#   {alloc,free}  edst spi proto src algo enckey authkey
#
# if algo="", then algo="3des-md5-96"
# if enckey="", then enckey=above, ditto for authkey.
# keys are not relevant for dealloc.
#
# note, proto must be = esp at present.

# the goal is to make something like:n
# ipsec spi --saref --af inet --edst 192.1.2.45 --spi 0x12345678 --proto esp --src 192.1.2.23 --esp 3des-md5-96 --enckey $enckey --authkey $authkey
#
#


# ROOT is "" in the UML testing environment, and /testing is mounted.

line=0

cat $ROOT/testing/klips/saref-alloc-01/allocfile1.txt | while read op edst spi proto src algo enckey authkey
do
    # set up defaults
    if [ -z "$algo" ]; then algo="3des-md5-96"; fi
    if [ -z "$enckey" ]; then enckey=$def_enckey;  fi
    if [ -z "$authkey"]; then authkey=$def_authkey; fi

    line=`expr $line + 1`
    #echo Input Line: $line

    case $op in
    \#*) ;;
    alloc) echo ipsec spi --saref --af inet --edst $edst --spi $spi --proto $proto --src $src --esp $algo --enckey $enckey --authkey $authkey;;
    free)  echo ipsec spi --saref --af inet --edst $edst --spi $spi --proto $proto --del;;
    esac
done



