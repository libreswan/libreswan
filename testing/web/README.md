# Example


See: http://libreswan.org/results/testing/


# Nuances


Some things, annoyingly, don't quite work right:

- new results slow to appear

  The local browser cache seems to get in the way.  One solution would
  be to append `<current-git-rev>` to the requests for .json files
  (this would bypass the cache).

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


# Maintenance


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


# Ideas


Some things could work better:

- can't select individual tests for comparison

  selecting an individual or small set of tests and comparing them
  across results would be nice

- can't bookmark a comparison

- an accumulative bar graph is probably a better way to represent the
  data (or at least the first-parents) that could then be overlaid
  with a scatter plot

- the graph should pan and zoom

- better colour scheme welcome

- rather than one-directory per test run, all the results should be
  put into a single directory (somewhat works)


# Setting Up a new Web Site


See the script:

    ./testing/web/setup.sh

make a copy, and hack it as needed.  It defaults to setting things up
in ~/results.

The only web requirement is d3.js (this is deliberate).


## Publishing Results


Use the script publish.sh:

  ./testing/web/publish.sh <repodir> <summarydir>

for instance:

  ./testing/web/publish.sh . ~/results/master

Nuances:

  - remote <summarydir> is broken

  - the <repodir> is required (defaulting to current directory would
    be nice VS batch testing requires separate script and test
    directories).

  - wonder what happens if multiple branches publish to a common
    directory, should be made to work


## Automated testing


Use the script:

    ./testing/web/tester.sh <repodir> <summarydir>

For instance:

    ./testing/web/tester.sh ~/libreswan ~/results/master

Nuances:

- it assumes that "git fetch" works; which is true for anonymous
  access to github

- probably need at least one directory before running this

- uses a heuristic to decide what to test next

- separate script and <repodir>s are required; when going back through
  history this script does evil things to <repodir> such as:

      git reset --hard


## Testing Updates


- set up a local web server

- run testing/web/local-rsync.sh to copy the useful bits of the web
  site

- run testing/web/local-install.sh to install local changes on top of
  the local copy


# References

