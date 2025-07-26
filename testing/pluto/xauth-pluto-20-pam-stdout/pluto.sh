#!/bin/sh

printenv | grep -e PAM -e PLUTO

echo HI from $0 PAM_USER=${PAM_USER} PAM_TYPE=${PAM_TYPE}

case ${PAM_USER} in
    good* ) exit 0 ;;
esac

exit 1
