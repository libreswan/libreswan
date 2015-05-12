#!/bin/sh -eu

# A script to put various build sequences through their paces.
j=-j$(grep ^processor /proc/cpuinfo | wc -l)
echo - $j
sleep 1

make $j distclean

make $j clean
make $j programs
make $j list
make $j manpages

find lib programs -name Makefile -print \
    | while read makefile ; do
	  dir=$(dirname $makefile)
	  case $dir in
	      lib/libbsdpfkey|programs/_realsetup.bsd)
		  echo Skipping directory $dir
		  continue;;
	  esac
	  if grep /library.mk $makefile 2>&1 ; then
	      echo $makefile - library.mk
	      make $j -C $dir clean    >> test.log
	      make $j -C $dir          >> test.log
	      make $j -C $dir clean    >> test.log
	      make $j -C $dir programs >> test.log
	  elif grep /program.mk $makefile 2>&1 ; then
	      echo $makefile - program.mk
	      make $j -C $dir clean    >> test.log
	      make $j -C $dir          >> test.log
	      make $j -C $dir clean    >> test.log
	      make $j -C $dir programs >> test.log
	  elif grep /subdirs.mk $makefile 2>&1 ; then
	      echo skipping $makefile - subdirs.mk
	  else
	      echo unknown $makefile
	  fi
      done
