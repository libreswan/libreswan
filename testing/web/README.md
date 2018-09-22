# Example


See: http://testing.libreswan.org/


# Manual Setup


To publish the results from running `make kvm-results` as a web page,
point the make variable `LSW_WEBDIR` at the web page's HTML directory.
For instance, either by adding it to Makefile.inc.local:

   $ mkdir /var/www/html/results
   echo LSW_WEBDIR=/var/www/html/results >> Makefile.inc.local

or your .profile:

   $ echo export LSW_WEBDIR=/var/www/html/results >> ~/.profile



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



# Improvements


Some things could work better:

- "good" and "wip" each list their errors separately

  So it is easier to identify "good" errors.

  Unfortunately, the raw data (found in `results.json`) isn't
  currently included in `summary.json`.

- examine (compare) individual tests

  For instance, select a test in the "Compare Results" tab would
  display (graph?) that test's history under a "Compare Test" tab.

  The raw test results are in <run>/<test>/OUTPUT/result.json.

- Bookmark comparisons

  For instance `results?hash,hash`.

  The required information seems to be in `location.search`.

- Use an accumulative bar graph instead of a scatter plot

  It probably better represents the data.  However, since it needs to
  also plot branches things could get interesting.

- Graph should pan and zoom

- trim older directories so the total is kept reasonable

- use rowspan=... in the summary table


# Automated Testing


## Setup


Automated testing uses the following:

- the html directory containing the published results

  For instance, to set up results/:

      $ mkdir -p results/

- the repository under test (aka slave)

  In addition to regular updates using "git fetch", this repository is
  switched to the commit being tested using "git reset --hard".

  Create a top-level Makefile.inc.local file in this directory to
  configure KVM_WORKERS and KVM_PREFIXES as required.

  For instance, to set up libreswan-web-slave/:

      $ git clone git@github.com:libreswan/libreswan.git libreswan-web-slave
      $ echo 'KVM_PREFIXES=w1. w2.' >> libreswan-web-slave/Makefile.inc.local
      $ echo 'KVM_WORKERS=2' >> libreswan-web-slave/Makefile.inc.local
      $ echo 'KVM_BUILD_HOST=build' >> libreswan-web-slave/Makefile.inc.local

- the repository containing the web sources and scripts (aka master),
  for instance libreswan-web-master/

  For instance, to set up libreswan-web-master/:

      $ git clone git@github.com:libreswan/libreswan.git libreswan-web-master

- the repository for rebuilding the web site (aka scratch) - optional

  When re-generating the results from a test run (for instance as part
  of rebuilding the web-site after a json file format change), this
  repository is "git reset --hard" to the original commit used to
  generate those results.

  For instance, to set up libreswan-web-scratch/:

      $ git clone git@github.com:libreswan/libreswan.git libreswan-web-scratch

- create the base domain (creating the base domain requires a TTY;
  blame kvm):

      $ ( cd libreswan-web-slave/ && make kvm-install-base-domain )


## Running


Assuming results are to be published in the directory results/ (see
above), the testing script is invoked as:

    $ rm -f nohup.out
    $ nohub ./libreswan-web-master/testing/web/tester.sh libreswan-web-slave results/ &
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

- the build fails so tester.sh, out of infinte caution, aborts

  Since tester.sh can't easily tell the difference between something
  harmless (such as a compilation error) and something more serious
  (such as corrupt KVMs) that would lead to the results directory
  filling with cascading failures, it aborts.

  Luckily compilation failures are very rare.

- the disk fills up

  Test result directory can be pruned without a restart. Once the
  current run finishes, runner.sh will re-build the web pages removing
  the deleted directories (you just need to wait).

  Included in the restart instructions below are suggests for how to
  find directories that should be pruned.

If a restart is required, the following are the recommended steps.

If you're in a hurry, reboot the machine then skip all the way to the
end with "restart":

- if necessary, crash the existing runner.sh:

  while killing runner.sh et.al. works, it is easier/quicker to just
  crash it by running the following a few times:

      $ ( cd libreswan-web-slave && make kvm-uninstall )

- (recommended, but optional) upgrade and reboot the test machine:

      $ sudo dnf upgrade -y
      $ sudo reboot

- (optional) cleanup and update the slave (tester.sh will do this
  anyway)

      $ ( cd libreswan-web-slave && git clean -f )
      $ ( cd libreswan-web-slave && git pull --ff-only )

- (optional) update the master repository:

  Remember to first check for local changes:

      $ ( cd libreswan-web-master && git status )
      $ ( cd libreswan-web-master && git pull --ff-only )

- (optional) examine (and perhaps delete) any test runs where tests
  have 'missing-output':

      $ grep '"output-missing"' results/*-g*-*/results.json | cut -d/ -f1-2 | sort -u

- (optional) examine (and perhaps delete) test runs with no
  results.json:

      $ ls -d results/*-g*-*/ | while read d ; do test -r $d/results.json || echo $d ; done

- (optional) examine (and perhaps delete) some test results:

  - use gime-work.sh to create a file containing, among other things,
    a list of test runs along with their commit and "interest" level
    (see below):

        $ ./libreswan-web-master/testing/web/gime-work.sh results libreswan-web-slave 2>&1 | tee commits.tmp

  - strip the raw list of everything but test runs; also exclude the
    most recent test run (so the latest result isn't deleted):

        $ grep TESTED: commits.tmp | tail -n +2 | tee tested.tmp

  - examine (and perhaps delete) the un-interesting (false) test runs

    Un-interesting commits do not modify the C code and are not a
    merge point. These are created when HEAD, which is tested
    unconditionally, isn't that interesting.  Exclude directories
    already deleted.

        $ awk '/ false$/ { print $2 }' tested.tmp | while read d ; do test -d "$d" && echo $d ; done

  - examine (and perhaps delete), a selection of more interesting
    (true) test runs.

    More interesting commits do modify the C code but are not a merge.
    Exclude directories already deleted.

        $ awk '/ true$/ { print $2 }' tested.tmp | while read d ; do test -d "$d" && echo $d ; done | shuf | tail -n +100

  - (optional) live update the summary directory

    	$ ( cd libreswan-web-master && make web-summarydir )

- restart <tt>tester.sh</tt>:

      $ rm -f nohup.out
      $ nohup ./libreswan-web-master/testing/web/tester.sh libreswan-web-slave results/ &
      $ tail -f nohup.out


## Rebuilding


From time-to-time the web site may require a partial or full rebuild.

For HTML (.html, .css and .js) files, the process is straight forward.
However, for the .json files, the process can be slow (and in the case
of the results, a dedicated git repository is needed).

- `make web [WEB_SCRATCH_REPODIR=.../libreswan-web-scratch]`

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

- `make web-results-json WEB_SCRATCH_REPODIR=.../libreswan-web-scratch`

  Update the `results.json` file in each test run's sub-directory.
  Very slow.  Requires a dedicated git repository.

  Touching the script `testing/utils/kvmresults.py`, which is used to
  generate results.json, will force an update.

- `make '$(WEB_SUMMARYDIR)/<run>/results.json' WEB_SCRATCH_REPODIR=.../libreswan-web-scratch`

  Update an individual test run's `results.json` file.  Slow.
  Requires a dedicated git repository.


# References
