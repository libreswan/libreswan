#!/bin/sh

#set -x
set -e

. $HOME/freeswan-regress-env.sh

recipients=`echo $NIGHTLY_WATCHERS | sed -e 's/,/ /g'`

#recipients='mcr@freeswan.org hugh@freeswan.org'

tmpfile=/tmp/msg$$
cat - >$tmpfile

sed -n -e '1,/^$/p' $tmpfile >$tmpfile.headers
sed -n -e '/^$/,$p' $tmpfile >$tmpfile.body

# encrypt body
#gpg --encrypt --armor -r mcr@freeswan.org --batch --yes $tmpfile.body

# reset home just in case.
HOME=/freeswan/users/build export HOME
PGPPATH=$HOME/.pgp export PGPPATH

pgp -eat $tmpfile.body $recipients 

( 
  cat $tmpfile.headers
  echo
  cat $tmpfile.body.asc 
) | cat | /usr/sbin/sendmail -t 

rm -f $tmpfile $tmpfile.headers $tmpfile.body $tmpfile.body.asc

