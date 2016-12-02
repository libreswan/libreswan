Publishing Results
------------------

See:

  http://libreswan.org/results/testing/

Nuances:

  - libreswan's repo contains knots: where the commit date is out of
    order; this is stumbled over

  - libreswan's repo contains plats: where a merge flips first-master
    with a development branch

  - an accumulative bar graph might represent the first-master better
    (but then what to do with branches, over lay just them as a
    scatter plot)

  - code needs to be more d3.js esque

  - interaction with the graphic would be nice

  - expect to occasionally prune the results as they take up a lot of
    space

  - better colour choice welcome

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
