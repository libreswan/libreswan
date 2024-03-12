# Example

See: http://testing.libreswan.org/


# Manual Setup

To publish the results from running `make kvm-results` as a web page,
point the make variable `WEB_SUMMARYDIR` at the web page's HTML
directory.  For instance, either by adding it to Makefile.inc.local:

   $ mkdir /var/www/html/results
   echo WEB_SUMMARYDIR=/var/www/html/results >> Makefile.inc.local


# Automated Testing

## Setup

Lets assume everything is being set up under ~/libreswan-web/:

      $ mkdir ~/libreswan-web/

With the following layout:

      ~/libreswan-web/rutdir/   # repository/directory under test
      ~/libreswan-web/benchdir/    # repository/directory driving the tests
      ~/libreswan-web/pool/              # directory containing VM disks et.al.
      ~/libreswan-web/results/           # directory containing published results

and optionally:

      /tmp/pool                          # tmpfs containing test vm disks
      ~/libreswan-web/scratch-repo/      # only used when rebuilding the world

- check that the host machine is correctly configured, see:

      https://libreswan.org/wiki/Test_Suite_-_KVM#Preparing_the_host_machine

- create the html directory where the results will be published

  For instance, to set up results/:

      $ cd ~/libreswan-web/
      $ mkdir results

- create the pool directory for storing permanent VM disk images

  For instance, assuming building and testing is being run from the
  sub-directory libreswan-web/:

      $ cd ~/libreswan-web/
      $ mkdir -p pool/

- checkout a dedicated repository for running tests (aka rutdir/)

  In addition to regular updates using "git fetch + git rebase", this
  repository is switched to the commit being tested using "git reset
  --hard".

      $ cd ~/libreswan-web/
      $ git clone https://github.com/libreswan/libreswan.git rutdir/

- configure the rutdir

  increase the number of reboots allowed in parallel (since a reboot
  seems to tie up two cores a rule of thumb is number-cores/2):

      $ echo 'KVM_WORKERS=2' >> rutdir/Makefile.inc.local

  increase the number of test domains (and give them unique prefixes
  so that they don't run with the default domain names):

      $ echo 'KVM_PREFIXES=w1. w2.' >> rutdir/Makefile.inc.local

  enable the wip tests:

      $ echo "KVM_TEST_FLAGS=--test-status 'good|wip'" >> rutdir/Makefile.inc.local

  move the test domains to /tmp (tmpfs):

      $ echo 'KVM_LOCALDIR=/tmp/pool' >> rutdir/Makefile.inc.local

- checkout a repository for the web sources and scripts (aka benchdir/)

      $ cd ~/libreswan-web/
      $ git clone https://github.com/libreswan/libreswan.git benchdir/


## Running

Assuming results are to be published in the directory
libreswan-web/results/ (see above), the testing script is invoked as:

Either:

    $ cd libreswan-web/
    $ rm -f nohup.out
    $ nohup benchdir/testing/web/tester.sh &
    $ tail -f nohup.out

or:

    $ cp /dev/null nohup.out
    $ nohup ./libreswan-web/benchdir/testing/web/tester.sh &
    $ tail -f nohup.out


## Restarting and Maintenance

The following things seem to go wrong:

- over time, the test results can get worse

  The symptom is an increasing number of "unresolved" test results
  with an error of "output-missing".  It happens because the domain
  took too long (more than 2 minutes!) to boot.

  tester.sh works around this by detecting the problem and then
  rebuilding domains, but sometimes even that doesn't work so things
  need to be cleaned up.

- the build crashes

  For instance a compiler error, or something more serious such as as
  corrupt VM.

  To mitigate this cascading, after a build failure, tester.sh will
  reset itself and wait for new changes before attempting a further
  build

- the disk fills up

  Test result directory can be pruned without a restart. Once the
  current run finishes, runner.sh will re-build the web pages removing
  the deleted directories (you just need to wait).

  Included in the restart instructions below are suggests for how to
  find directories that should be pruned.

If a restart is required, the following are the recommended steps (if
you're in a hurry, reboot the machine then skip all the way to the end
with "restart"):

- if necessary, crash the existing runner.sh:

  while killing runner.sh et.al. works, it is easier/quicker to just
  crash it by running the following a few times:

      $ cd libreswan-web/
      $ ( cd rutdir/ && make kvm-uninstall )

- (optional, but recommended) upgrade and reboot the test machine:

      $ sudo dnf upgrade -y
      $ sudo reboot

- (optional) cleanup and update the rutdir/ (tester.sh will do this
  anyway)

      $ cd libreswan-web/
      $ ( cd rutdir/ && git clean -f )
      $ ( cd rutdir/ && git pull --ff-only )

- (optional) update the benchdir/ repository:

  Remember to first check for local changes:

      $ cd libreswan-web/
      $ ( cd benchdir/ && git status )
      $ ( cd benchdir/ && git pull --ff-only )

- (optional) examine, and perhaps delete, any test runs where tests
  have 'missing-output':

      $ cd libreswan-web/
      $ grep '"output-missing"' results/*-g*-*/results.json | cut -d/ -f1-2 | sort -u

- (optional) examine (and perhaps delete) test runs with no
  results.json:

      $ cd libreswan-web/
      $ ls -d results/*-g*-*/ | while read d ; do test -r $d/results.json || echo $d ; done

- (optional) examine, and perhaps delete, some test results:

  - use gime-work.sh to create a file containing, among other things,
    a list of test runs along with their commit and "interest" level
    (see below):

        $ ./benchdir/testing/web/gime-work.sh results rutdir/ 2>&1 | tee commits.tmp

  - strip the raw list of everything but test runs; also exclude the
    most recent test run (so the latest result isn't deleted):

        $ grep TESTED: commits.tmp | tail -n +2 | tee tested.tmp

  - examine, and perhaps delete, the un-interesting (false) test runs

    Un-interesting commits do not modify the C code and are not a
    merge point. These are created when HEAD, which is tested
    unconditionally, isn't that interesting.  Exclude directories
    already deleted.

        $ awk '/ false$/ { print $2 }' tested.tmp | while read d ; do test -d "$d" && echo $d ; done

  - examine, and perhaps delete, a selection of more interesting
    (true) test runs.

    More interesting commits do modify the C code but are not a merge.
    Exclude directories already deleted.

        $ awk '/ true$/ { print $2 }' tested.tmp | while read d ; do test -d "$d" && echo $d ; done | shuf | tail -n +100

- start <tt>tester.sh</tt>, see above


## Rebuilding

From time-to-time the web site may require a partial or full rebuild.

For HTML (.html, .css and .js) files, the process is straight forward.
However, for the .json files, the process can be slow (and in the case
of the results, a dedicated git repository is needed).

- create a repository for rebuilding the web site (aka scratch/)

  When re-generating the results from a test run (for instance as part
  of rebuilding the web-site after a json file format change), this
  repository is "git reset --hard" to the original commit used to
  generate those results.

  For instance, to set up libreswan-web/scratch/:

      $ cd libreswan-web/
      $ git clone https://github.com/libreswan/libreswan.git scratch/

- `make web [WEB_SCRATCH_REPODIR=.../libreswan-web/scratch]`

  Update the web site.

  If WEB_SCRATCH_REPODIR is specified, then the result.json files in
  the test run sub-directories under $(WEB_SUMMARYDIR) are also
  updated.

- `make web-results-html`

  Update any out-of-date HTML (.html, .css and .json) files in the
  results sub-directories.

  Touching the source file `testing/web/results.html` will force an
  update.

- `make web-commits-json`

  Update the commits.json file which contains a table of all the
  commits.  Slow.

  Touching the script `testing/web/json-commit.sh`, which is used to
  create the files, will force an update.  So too will deleting the
  .../commits/ directory.

- `make web-results-json WEB_SCRATCH_REPODIR=.../libreswan-web/scratch`

  Update the `results.json` file in each test run's sub-directory.
  Very slow.  Requires a dedicated git repository.

  Touching the script `testing/utils/kvmresults.py`, which is used to
  generate results.json, will force an update.

- `make '$(WEB_SUMMARYDIR)/<run>/results.json' WEB_SCRATCH_REPODIR=.../libreswan-web/scratch`

  Update an individual test run's `results.json` file.  Slow.
  Requires a dedicated git repository.


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


# Archiving

After the release, save the results to elsewhere.

- shut down the tester

  With out this it will likely try to test results that have been
  archived.  Something like:

      ( cd libreswan-web/test-repo/ && ./kvm kill )
      pkill tester

- clean up scratch directories (they get rebuilt):

      rm -rf results/commits*
      rm -rf results/tests

   well perhaps not the second, later

- set up the variables

      o=v4.7
      n=v4.8

- make some paths easier:

- create the archive directory:

      mkdir ~/${o}-${n}

- move results from previous release:

      mv ~/results/${o}-* ~/${o}-${n}

- copy result from latest release (so results are bookended with by
  releases) (tester.sh given a chance will seek out and test ${n}-0):

      cp -r ~/results/${n}-0-* ~/${o}-${n}

- now clean the archive of old logs (these should match the pattern
  OUTPUT/*):

      find ~/${o}-${n} -name 'debug.log.gz' | xargs rm -v
      find ~/${o}-${n} -name 'pluto.log' -print | xargs rm -v
      find ~/${o}-${n} -name 'iked.log' -print | xargs rm -v
      find ~/${o}-${n} -name 'charon.log' -print | xargs rm -v

- check for other files:

      find ~/${o}-${n} -name '*.log.gz' -print # delete?

  this finds some bonus stuff in OUTPUT which should be added to
  above

- check for stray logs:

      find ~/${o}-${n} -name '.log' -print # delete?

  this finds things like kvm-check.log which should be compressed

- finally re-generate the pages in the archive:

      ( cd ~/libreswan-web/script-repo/ && make WEB_SUMMARYDIR=~/${o}-${n} web-summarydir )

- and restart tester.sh

  Note the addition of ${n} to specify the commit to start from.

      cp /dev/null nohup.out ; nohup ;
      ./libreswan-web/benchdir/testing/web/tester.sh ${n} &


# Improvements

Some things could work better:

- examine (compare) individual tests

  For instance, select a test in the "Compare Results" tab would
  display (graph?) that test's history under a "Compare Test" tab.

  The raw test results are in <run>/<test>/OUTPUT/result.json.

- Use an accumulative bar graph instead of a scatter plot

  It probably better represents the data.  However, since it needs to
  also plot branches things could get interesting.

- Graph should pan and zoom

- trim older directories so the total is kept reasonable

- use rowspan=... in the summary table
