# convert a host path into a guest path, for libreswan
#
# Copyright (C) 2023  Andrew Cagney
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

import os
import re
from fab import virsh

def guest_path(guest, host_path):

    # Extract the 9p mount points from LIBVIRT's XML building a map
    # from guest 9p name (XML target) to the host path (XML source.
    #
    # The code works kind of but not really like a state machine.
    # Specific lines trigger actions.
    mount_points = {}
    for line in guest.dumpxml().splitlines():
        if re.compile("<filesystem type='mount' ").search(line):
            source = ""
            target = ""
            continue
        match = re.compile("<source dir='([^']*)'").search(line)
        if match:
            source = match.group(1)
            # Strip trailing "/" along with other potential quirks
            # such as the mount point being a soft link.
            source = os.path.realpath(source)
            continue
        match = re.compile("<target dir='([^']*)'").search(line)
        if match:
            target = match.group(1)
            continue
        if re.compile("<\/filesystem>").search(line):
            guest.logger.debug("filesystem '%s' '%s'", target, source)
            mount_points[target] = source
            continue

    # Extract /etc/fstab from the domain.
    #
    # Because of the auto-mounter /etc/fstab is needed as that
    # contains what will be mounted (where as mount output only
    # contains what has been mounted).
    #
    # The output is saved in the first group (remember 0 is
    # everything) and then converted to "text".  Danger binary data!
    #
    # Merge this into .run()?
    guest._console.child.sendline("cat /etc/fstab")
    if guest._console.child.expect([rb'(.*)\s+' + guest._console.prompt.pattern,
                                    guest._console.prompt],
                                   timeout=virsh.TIMEOUT,
                                   searchwindowsize=-1):
        raise pexpect.TIMEOUT("fstab content not found")
    status = guest._console._check_prompt()
    if status:
        raise AssertionError("extracting fstab failed: %s", status)
    guest.logger.debug("status %s match %s", status, guest._console.child.match)
    output = guest._console.child.match
    fstab = output.group(1).decode('utf-8')

    # Convert the fstab into a device (NFS path or 9p target) to local
    # directory map.
    #
    # look for NFS and 9p mounts and add them to the table
    mounts = []
    for line in fstab.splitlines():
        guest.logger.debug("line: %s", line)
        if line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        device = fields[0]
        mount = fields[1]
        fstype = fields[2]
        if fstype == "nfs":
            guest.logger.debug("NFS mount '%s''%s'", device, mount)
            device = device.split(":")[1]
            # switch to utf-8
            mounts.append((device, mount))
        elif fstype == "9p":
            if device in mount_points:
                guest.logger.debug("9p mount '%s' '%s'", device, mount)
                device = mount_points[device]
                mounts.append((device, mount))
            else:
                guest.logger.info("9p mount '%s' '%s' is not in domain description", device, mount)
        else:
            guest.logger.debug("skipping %s mount '%s' '%s'", fstype, device, mount)

    mounts = sorted(mounts, key=lambda item: item[0], reverse=True)
    guest.logger.debug("ordered mounts %s", mounts);

    # Use the mounts map to match the host-path converting it into a
    # guest-path.
    #
    # Note that MOUNTS is sorted in reverse order so that
    # /source/testing comes before /source.  This way the longer path
    # is matched first.
    host_path = os.path.realpath(host_path)
    for host_directory, guest_directory in mounts:
        guest.logger.debug("host %s guest %s path %s", host_directory, guest_directory, host_path)
        if os.path.commonprefix([host_directory, host_path]) == host_directory:
            # Found the local directory containing path that is
            # mounted on the guest; now convert that into an
            # absolute guest path.
            return guest_directory + host_path[len(host_directory):]

    raise AssertionError("the host path '%s' is not mounted on the guest %s" % (host_path, guest))
