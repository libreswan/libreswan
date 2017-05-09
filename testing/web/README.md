# Example


See: http://libreswan.org/results/testing/


# Local Setup


To publish results from kvm-test locally, point WEBDIR at the
directory under which results should be published.  For instance, by
adding:

   WEBDIR=/var/www/html/results

to Makefile.inc.local


# Nuances


Some things, annoyingly, don't quite work right:

- comparisons sometimes loose a result

  The code fetching all the json result tables is likely racy, when
  too may results are clicked too fast a result goes missing.  The
  work around is to de-select and then re-select the missing result.

- libreswan's repo contains "knots"

  When following a linear history (parent links), the commit dates
  normally decrease.  In this repo they some times increase resulting
  in graph doubling back on itself.

- libreswan's repo contains "plats"

  As a generalization, is good to merge local changes onto the remote
  first-parent branch and not the reverse.  Unfortunately `git pull
  (git merge)` does the reverse by default.  The result is that
  first-parent keeps switching with development branches.

- clicking links toggls a results selection

  For instance, control-click a result's subject hash link (to open a
  new tab displaying the diff)) also toggls the results appearance
  under the comparison tab

- if the build fails, no entry for it appears


# Ideas


Some things could work better:

- Errors column should be broken down further into "good" and "wip";
  unfortunately that data currently isn't available

- same for the graph so it goes, good, fail, good, fail, unresolved,
  untested?

- can't select individual tests for comparison

  selecting an individual or small set of tests and comparing them
  across results would be nice

- can't bookmark a comparison

- an accumulative bar graph is probably a better way to represent the
  data (or at least the first-parents) that could then be overlaid
  with a scatter plot

- the graph should pan and zoom

- better colour scheme welcome

- trim older directories so the total is kept reasonable

# Automated Testing


## Setup


Automated testing requires two libreswan repositories:

- the repository under test (aka slave)

  This repository is constantly updated (for instance, pulling new
  commits from upstream, or switching to an old commit using git reset
  --hard).

  Create a top-level Makefile.inc.local file in this directory to
  configure KVM_WORKERS and KVM_PREFIXES as required.

- the repository containing the test scripts (aka master)

  This repository is left unchanged.

for instance:

    $ git clone git@github.com:libreswan/libreswan.git libreswan-slave
    $ git clone git@github.com:libreswan/libreswan.git libreswan-master


## Running


Assuming results are to be published in /var/www/html/results, the
testing script is invoked as:

    libreswan-master/testing/web/tester.sh libreswan-slave /var/www/html/results/


## Maintenance


From time to time the test results are seen to decay - an increasing
number of tests fail with a result of "unresolved" and an error of
"output-missing".  The problem is domains taking too long to boot
(over 2 minutes each).

The fix is to restart the machine and then re-build the test domains.
It is also a good opportunity to perform some more general
maintenance.

- upgrade and reboot the test machine:

      dnf upgrade -y ; reboot

- delete the existing domains:

      cd $BUILDDIR && make kvm-uninstall

- update the build tree to latest:

      cd $BUILDDIR && git pull --ff-only

- delete result directories with missing output; to list the
  directories:

      cd $WEBDIR && grep '"output-missing"' */results.json | cut -d/  -f1 | sort -u # | xargs rm -rf

- delete result directories with incomplete output; to list the
  directories:

      cd $WEBDIR && ls -d */ | while read d ; do test -r $d/results.json || echo $d ; done # | xargs rm -rf

- compress any log files:

      cd $WEBDIR && find * -path '*/OUTPUT/*.log' -type f -print | xargs bzip2 -v -9

- restart <tt>tester.sh</tt>:

      cd && nohup $SCRIPTDIR/testing/web/tester.sh $BUILDDIR $WEBDIR


# References
