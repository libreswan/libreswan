#!/bin/sh

basedir=${HOME}/results

if test $# -lt 1; then
    cat <<EOF > /dev/stderr

Usate:

  $0 <repodir> [ <basedir> ]

Run the testsuite in <repodir> publishing the results
in <basedir> (default ${basedir}) under <host>/<gitver>.

EOF
    exit 1
fi

# exit if anything looks weird and be verbose.
set -euxv

# where the testsuite lives
repodir=$(cd $1 && pwd) ; shift
testingdir=${repodir}/testing

# where to put results
if test $@ -ge 1; then
    basedir=$(cd $1 && pwd) ; shift
fi

# where the scripts live
webdir=$(cd $(dirname $0) && pwd)
utilsdir=$(cd ${webdir}/../utils && pwd)

cd ${repodir}
gitstamp=$(make showversion)
# go backwards from gitstamp to get the git:rev and git:date; this
# since updates will use the same scripts, this confirms that they are
# working.
rev=$(${webdir}/gime-git-rev.sh ${repodir} ${gitstamp})
date=$(${webdir}/gime-git-date.sh ${repodir} ${rev})
version=$(echo ${date} ${gitstamp} | sed -e 's/://' -e 's/ /-/g')

destdir=${basedir}/$(hostname)/${version}
echo ${destdir}

mkdir -p ${destdir}

# Rebuild/run; but only if previous attempt didn't crash badly.
for target in distclean kvm-install kvm-retest kvm-shutdown ; do
    # because "make ... | tee bar" does not see make's exit code, use
    # a file as a hack.
    ok=${destdir}/make-${target}.ok
    if test ! -r ${ok} ; then
	make ${target}
	touch ${ok}
    fi
    # above created file?
    test -r ${ok}
done


# Copy over all the tests.
${webdir}/rsync-tests.sh --no-checkout ${repodir} ${destdir}


# Copy over all the results.
${webdir}/rsync-results.sh ${repodir} ${destdir}


# rebuild-results.sh will delete this file
${webdir}/build-results --no-checkout ${repodir} ${destdir}


# rebuild-summary.sh will delete this file
${webdir}/build-summary --no-checkout ${repodir} ${basedir}
