#!/bin/bash

# kmodtool - Helper script for building kernel module RPMs
#            An original version appeared in Fedora. This version is
#            generally called only by the %kernel_module_package RPM macro
#            during the process of building Driver Update Packages (which
#            are also known as "kmods" in the Fedora community).
#
# Copyright (c) 2003-2010 Ville Skyttä <ville.skytta@iki.fi>,
#                         Thorsten Leemhuis <fedora@leemhuis.info>
#                         Jon Masters <jcm@redhat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# Changelog:
#
#            2010/07/28 - Add fixes for filelists in line with LF standard
#                       - Remove now defunct "framepointer" kernel variant
#                       - Change version to "rhel6-rh2" as a consequence.
#
#            2010/01/10 - Simplified for RHEL6. We are working on upstream
#                         moving to a newer format and in any case do not
#                         need to retain support for really old systems.

shopt -s extglob

myprog="kmodtool"
myver="rhel6-rh2"
knownvariants=@(debug|kdump)
kmod_name=
kver=
verrel=
variant=

get_verrel ()
{
  verrel=${1:-$(uname -r)}
  verrel=${verrel%%$knownvariants}
}

print_verrel ()
{
  get_verrel $@
  echo "${verrel}"
}

get_variant ()
{
  get_verrel $@
  variant=${1:-$(uname -r)}
  variant=${variant##$verrel}
  variant=${variant:-'""'}
}

print_variant ()
{
  get_variant $@
  echo "${variant}"
}

get_filelist() {
	local IFS=$'\n'
	filelist=($(cat))

	if [ ${#filelist[@]} -gt 0 ];
	then
		for ((n = 0; n < ${#filelist[@]}; n++));
		do
			line="${filelist[n]}"
			line=$(echo "$line" \
				| sed -e "s/%verrel/$verrel/g" \
				| sed -e "s/%variant/$variant/g" \
				| sed -e "s/%dashvariant/$dashvariant/g" \
				| sed -e "s/%dotvariant/$dotvariant/g" \
				| sed -e "s/\.%1/$dotvariant/g" \
				| sed -e "s/\-%1/$dotvariant/g" \
				| sed -e "s/%2/$verrel/g")
			echo "$line"
		done
	else
		echo "%defattr(644,root,root,755)"
		echo "/lib/modules/${verrel}${dotvariant}"
	fi
}

get_rpmtemplate ()
{
    local variant="${1}"
    local dashvariant="${variant:+-${variant}}"
    local dotvariant="${variant:+.${variant}}"

    echo "%package       -n kmod-${kmod_name}${dashvariant}"

    if [ -z "$kmod_provides_summary" ]; then
        echo "Summary:          ${kmod_name} kernel module(s)"
    fi

    if [ -z "$kmod_provides_group" ]; then
        echo "Group:            System Environment/Kernel"
    fi

    if [ ! -z "$kmod_version" ]; then
        echo "Version: %{kmod_version}"
    fi

    if [ ! -z "$kmod_release" ]; then
        echo "Release: %{kmod_release}"
    fi

    # Turn off the internal dep generator so we will use the kmod scripts.
    echo "%global _use_internal_dependency_generator 0"

    cat <<EOF
Provides:         kabi-modules = ${verrel}${dotvariant}
Provides:         ${kmod_name}-kmod = %{?epoch:%{epoch}:}%{version}-%{release}
Requires(post):   /sbin/depmod
Requires(postun): /sbin/depmod
EOF

    if [ "no" != "$nobuildreqs" ]
    then
        echo "BuildRequires: kernel${dashvariant}-devel"
    fi

    if [ "" != "$override_preamble" ]
    then
        cat "$override_preamble"
    fi

cat <<EOF
%description   -n kmod-${kmod_name}${dashvariant}
This package provides the ${kmod_name} kernel module(s) built
for the Linux kernel using the %{_target_cpu} family of processors.
EOF

##############################################################################
## The following are not part of this script directly, they are scripts     ##
## that will be executed by RPM during various stages of package processing ##
##############################################################################

cat <<EOF
%post          -n kmod-${kmod_name}${dashvariant}
echo "Working. This may take some time ..."
if [ -e "/boot/System.map-${verrel}${dotvariant}" ]; then
    /sbin/depmod -aeF "/boot/System.map-${verrel}${dotvariant}" "${verrel}${dotvariant}" > /dev/null || :
fi
modules=( \$(find /lib/modules/${verrel}${dotvariant}/extra/${kmod_name} | grep '\.ko$') )
if [ -x "/sbin/weak-modules" ]; then
    printf '%s\n' "\${modules[@]}" | /sbin/weak-modules --add-modules
fi
echo "Done."
EOF

cat <<EOF
%preun         -n kmod-${kmod_name}${dashvariant}
rpm -ql kmod-${kmod_name}${dashvariant}-%{version}-%{release}.$(arch) | grep '\.ko$' > /var/run/rpm-kmod-${kmod_name}${dashvariant}-modules
EOF

cat <<EOF
%postun        -n kmod-${kmod_name}${dashvariant}
echo "Working. This may take some time ..."
if [ -e "/boot/System.map-${verrel}${dotvariant}" ]; then
    /sbin/depmod -aeF "/boot/System.map-${verrel}${dotvariant}" "${verrel}${dotvariant}" > /dev/null || :
fi
modules=( \$(cat /var/run/rpm-kmod-${kmod_name}${dashvariant}-modules) )
rm /var/run/rpm-kmod-${kmod_name}${dashvariant}-modules
if [ -x "/sbin/weak-modules" ]; then
    printf '%s\n' "\${modules[@]}" | /sbin/weak-modules --remove-modules
fi
echo "Done."
EOF

echo "%files         -n kmod-${kmod_name}${dashvariant}"
if [ "" == "$override_filelist" ];
then
    echo "%defattr(644,root,root,755)"
    echo "/lib/modules/${verrel}${dotvariant}/"
    echo "%config /etc/depmod.d/kmod-${kmod_name}.conf"
    echo "%doc /usr/share/doc/kmod-${kmod_name}-%{version}/"
else
    cat "$override_filelist" | get_filelist
fi
}

print_rpmtemplate ()
{
  kmod_name="${1}"
  shift
  kver="${1}"
  get_verrel "${1}"
  shift
  if [ -z "${kmod_name}" ] ; then
    echo "Please provide the kmodule-name as first parameter." >&2
    exit 2
  elif [ -z "${kver}" ] ; then
    echo "Please provide the kver as second parameter." >&2
    exit 2
  elif [ -z "${verrel}" ] ; then
    echo "Couldn't find out the verrel." >&2
    exit 2
  fi

  for variant in "$@" ; do
      if [ "default" == "$variant" ];
      then
            get_rpmtemplate ""
      else
            get_rpmtemplate "${variant}"
      fi
  done
}

usage ()
{
  cat <<EOF
You called: ${invocation}

Usage: ${myprog} <command> <option>+
 Commands:
  verrel <uname>                               
    - Get "base" version-release.
  variant <uname>                               
    - Get variant from uname.
  rpmtemplate <mainpgkname> <uname> <variants> 
    - Return a template for use in a source RPM
  version  
    - Output version number and exit.
EOF
}

invocation="$(basename ${0}) $@"
while [ "${1}" ] ; do
  case "${1}" in
    verrel)
      shift
      print_verrel $@
      exit $?
      ;;
    variant)
      shift
      print_variant $@
      exit $?
      ;;
    rpmtemplate)
      shift
      print_rpmtemplate "$@"
      exit $?
      ;;
    version)
      echo "${myprog} ${myver}"
      exit 0
      ;;
    *)
      echo "Error: Unknown option '${1}'." >&2
      usage >&2
      exit 2
      ;;
  esac
done

# Local variables:
# mode: sh
# sh-indentation: 2
# indent-tabs-mode: nil
# End:
# ex: ts=2 sw=2 et
