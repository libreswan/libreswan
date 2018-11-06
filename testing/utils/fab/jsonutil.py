# Some json parsing functions.
#
# Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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

import json
from datetime import datetime, timezone

class result:
    directory = "directory"
    testname = "testname"
    expect = "expect"
    result = "result"
    hosts = "hosts"
    issues = "errors" # for historic reasons, "issues" are publicly called "errors"
    script_time = "script_time"
    boot_time = "boot_time"
    hosts = "hosts"
    # keep things going
    time = "time"
    runtime = "runtime"


def load(io):
    try:
        return json.load(io)
    except ValueError:
        return None

def loads(s):
    try:
        return json.loads(s)
    except ValueError:
        return None

def default(obj):
    if hasattr(obj, "json") and callable(getattr(obj, "json")):
        return obj.json()
    if hasattr(obj, "isoformat") and callable(getattr(obj, "isoformat")):
        # date/time objects
        if not obj.utcoffset():
            # add local timezone to "naive" local time
            # https://stackoverflow.com/questions/2720319/python-figure-out-local-timezone
            tzinfo = datetime.now(timezone.utc).astimezone().tzinfo
            obj = obj.replace(tzinfo=tzinfo)
        # convert to UTC
        obj = obj.astimezone(timezone.utc)
        # strip the UTC offset
        obj = obj.replace(tzinfo=None)
        return obj.isoformat() + "Z"
    elif hasattr(obj, "__str__") and callable(getattr(obj, "__str__")):
        return str(obj)
    else:
        print("obj:", obj)
        raise TypeError(obj)

def dump(j, io):
    json.dump(j, io, indent=2, default=default)

def dumps(s):
    return json.dumps(s, default=default)

def ftime(t):
    """Format the time"""
    return t.strftime("%Y-%m-%d %H:%M")

def ptime(s):
    """Tries to parse what is assumed to be local time"""
    # print(s)
    for hms in ["%H:%M", "%H:%M:%S", "%H:%M:%S.%f"]:
        for t in [" ", "T"]:
            try:
                t = datetime.strptime(s, "%Y-%m-%d" + t + hms)
                # print(t)
                return t
            except:
                None
    return None
