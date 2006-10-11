#!/bin/sh

set -e

#### defaults

be_verbose=
do_debug=

klips_git=/mara1/git/klips
openswan_git=`pwd`
klips_revs="v2.6.16.18..HEAD"

interesting_dirs="net/ipsec include/openswan* include/pfkey* include/crypto/ include/des include/zlib/ crypto/ocf"

# patch for building ocf ...
build_patches_for="crypto/Kconfig crypto/Makefile include/linux/miscdevice.h include/linux/uio.h"

# patch for fixes ...
# TODO: remove later
build_patches_for="$build_patches_for crypto/cipher.c drivers/char/random.c include/linux/random.h"

#### helper functions

function bail {
        echo "$@" >&2
        echo "try $0 -h" >&2
        exit 1
}

function vecho {
        [ -z $be_verbose ] || echo "$@"
}

function help {
        cat <<END 
$0 [-k <klips_git_tree>] [-r <git_revs_for_diffs>] [-h]

options:

    -k <klips_git_tree>       git tree to pull in
    -r <git_revs_for_diffs>   revisions to use for diff
    -v                        be verbose
    -d                        debug mode (set -x)
    -h                        this help

defaults:
     klips_git_tree          $klips_git
     git_revs_for_diffs      $klips_revs

END
        exit 0
}

#### parse command line

while ! [ -z "$1" ] ; do
        word="$1"
        shift
        case $word in
            -h)
                help
                ;;
            -d)
                do_debug=1
                ;;
            -v)
                be_verbose=1
                ;;
            -k)
                klips_git=$1
                shift
                ;;
            -r)
                klips_revs=$1
                shift
                ;;
        esac
done

#### process/validate options

[ -z "$do_debug" ] || set -x

[ -d "$klips_git"            ] || bail "$0: not a directory: $klips_git"
[ -d "$klips_git/.git/"      ] || bail "$0: not a git tree: $klips_git"
[ -d "$klips_git/net/ipsec/" ] || bail "$0: not a klips tree: $klips_git"
klips_git=$(cd $klips_git ; pwd)

( cd $klips_git && git-rev-list $klips_revs -- > /dev/null) || bail "$0: $klips_revs is not a valid revision list"

vecho "pull from:  $klips_git"
vecho "pull into:  $openswan_git"
vecho "patch revs: $klips_revs"

#### step 1... copy over all the files that don't require patching
(       
        cd $klips_git 
        filter_for_patch_files=$(echo $build_patches_for | sed 's, ,\\|,g')
        find $interesting_dirs -type f | grep -v "$filter_for_patch_files" | cpio -pd $openswan_git/linux 
)

#### step 2... cleanup after the copy
(
        cd $openswan_git/linux/net/ipsec
        if [ -f Makefile ]; then mv Makefile Makefile.fs2_6; fi
        for dir in des aes alg 
        do
                if [ -f $dir/Makefile ]; then mv $dir/Makefile $dir/Makefile.fs2_6; fi
        done
        rm version.c Makefile.ver
)

#### step 3... generate the .fs2_6.patch files
(
        cd $klips_git 
        for file in $build_patches_for ; do
                patch=$openswan_git/linux/$file.fs2_6.patch
                mkdir -p $(dirname $patch)
                git-diff "$klips_revs" -- $file > $patch
        done
)

#### done
echo success
