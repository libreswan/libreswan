# Some json parsing functions.
#
# Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.

# Implement log-level inversion.
#
# Ref: https://docs.python.org/2/howto/logging.html#logging-flow
#
# By default, a parent (root) logger, regardless of its log-level,
# will log all the records logged by a child.  For instance, if a
# child logger is logging at DEBUG-level, then the parent will log
# (display on the console) those DEBUG-level records even when it has
# been configured to log only INFO-level records.  This is because the
# default log-level ("Logger enabled for level of call?") check is
# only applied once at record-creation.
#
# This code allows DEBUG-level logging to a file, while simultaneously
# (the inversion) restricting console log records to just INFO-level
# say.

# Add '"%(name)s %(runtime)s: ' prefix to all messages.
#
# Ref: https://docs.python.org/3.6/howto/logging-cookbook.html#using-loggeradapters-to-impart-contextual-information
#
# It uses the msg edit hack as that seems simple and straight forward.
# The timer used to generate "runtime" can also nest/stack times
# making it easy to track sub-processes.

import json
from datetime import datetime

class result:
    testname = "testname"
    expect = "expect"
    result = "result"
    time = "time"
    runtime = "runtime"
    host_results = "host_results"

class table:
    rundir = "runDir"
    suffix = "suffix"
    summary = "summary"
    columns = "columns"
    rows = "rows"

class summary:
    passed = "passed"
    failed = "failed"
    incomplete = "incomplete"
    total = "Total"
    # end-time: YYYY-MM-DD HH:MM see ftime/ptime.
    date = "date"
    runtime = "runtime"
    directory = "directory"

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

def dump(j, io):
    json.dump(j, io, indent=2)

def dumps(s):
    return json.dumps(s)

def ftime(t):
    return t.strftime("%Y-%m-%d %H:%M")

def ptime(s):
    datetime.strptime(s, "%Y-%m-%d %H:%M")
