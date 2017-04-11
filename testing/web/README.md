Publishing Results
------------------

See:

  http://libreswan.org/results/testing/

Set Up
------

See the script:

    ./testing/web/setup.sh

make a copy, and hack it as needed.  It defaults to setting things up
in ~/results.

The only web requirement is d3.js (this is deliberate).

Publishing Results
------------------

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

Automated testing
-----------------

Use the script:

  ./testing/web/tester.sh <repodir> <summarydir>

For instance:

  ./testing/web/tester.sh ~/libreswan ~/results/master

Nuances:

  - it assumes that "git fetch" works; which is true for anonymous
    access to github

  - probably need at least one directory before running this

  - uses a heuristic to decide what to test next

  - separate script and <repodir>s are required; when going back
    through history this script does evil things to <repodir> such as:
    git reset --hard.


Testing Updates
---------------

- set up a local web server

- run testing/web/local-rsync.sh to copy the useful bits of the web
  site

- run testing/web/local-install.sh to install local changes on top of
  the local copy
