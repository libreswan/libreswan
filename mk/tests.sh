#!/bin/sh -eu

# A script to put various build sequences through their paces.

make programs

find lib -name Makefile -print \
    | while read makefile ; do
	  dir=$(dirname $makefile)
	  case $dir in
	      lib/libbsdpfkey)
		  echo Skipping directory $dir
		  continue;;
	  esac
	  if grep /library.mk $makefile 2>&1 ; then
	      echo $dir - library.mk
	      make -C $dir clean
	      make -C $dir
	      make -C $dir
	  elif grep /programs.mk $makefile 2>&1 ; then
	      echo skipping $dir - programs.mk
	  elif grep /subdirs.mk $makefile 2>&1 ; then
	      echo skipping $dir - subdirs.mk
	  else
	      echo unknown $dir
	  fi
      done
