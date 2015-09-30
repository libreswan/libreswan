# Some argument parsing functions.
#
# Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
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

import logging
import sys
from datetime import datetime
from fab import argutil

# Avoid having code include both "logging" and "logutil" by
# re-exporting useful stuff here.  Good idea?  Perhaps.
ERROR = logging.ERROR
DEBUG = logging.DEBUG
INFO = logging.INFO
NONE = 100 # something large

_STDOUT_HANDLER = None
_DEBUG_HANDLER = None
_LOG_LEVEL = "info"

TIMER = None

def __init__():

    global _STDOUT_HANDLER
    _STDOUT_HANDLER = logging.StreamHandler(sys.stdout)
    _STDOUT_HANDLER.setFormatter(logging.Formatter("%(message)s"))
    _STDOUT_HANDLER.setLevel(_LOG_LEVEL.upper())

    global _DEBUG_HANDLER
    _DEBUG_HANDLER = DebugHandler()
    _DEBUG_HANDLER.setFormatter(logging.Formatter("%(levelname)s %(message)s"))

    # Force the root-logger to pass everything on to the handlers; and
    # then let the handlers filter just their log-records.
    logging.basicConfig(level=logging.NOTSET,
                        handlers=[_STDOUT_HANDLER, _DEBUG_HANDLER])

    global TIMER
    TIMER = Timer()


def getLogger(name, *suffixes):
    """Return the logger identified by NAME and SUFFIXES

    To, hopefully, make the logger's name more friendly, any module
    prefixes are stripped, and qualifying suffixes are appended.  For
    instance, "fab.shell,east" becomes "shell east" in log messages.

    XXX: An alternative construct might be: "fab.shell,east" becomes
    "fab.shell.east"; but "shell,east" becomes "shell east".

    """

    # name == __name__ == a.b.c == [0]="a.b" [1]="." [2]="c"
    name = name.rpartition(".")[2]
    for suffix in suffixes:
        if suffix:
            name += " " + suffix
    logger = logging.getLogger(name)

    # Log messages are first filtered by logger-level and then
    # filtered by handler-level.  This disables the logger filter so
    # that all messages get passed on to the handlers and their
    # filters.
    #
    # A more complicated alternative would be to set this, across all
    # loggers, dependent on --log-level and --debug.
    logger.setLevel(logging.NOTSET + 1)

    return CustomMessageAdapter(logger, "%(name)s %(runtime)s: ",
                                name=name, runtime=TIMER)


def add_arguments(parser):
    group = parser.add_argument_group("Logging arguments",
                                      "Options for directing logging level and output")
    group.add_argument("--log-level", default=None,
                       help=("console log level"
                             " (default: " + _LOG_LEVEL + ")"))
    group.add_argument("--debug", "-d", default=None, metavar="FILE",
                       type=argutil.stdout_or_open_file,
                       help=("write a debug-level log to %(metavar)s"
                             "; specify '-' to write output to the screeen (stdout)"
                             "; append '+' to append-to instead of overwrite %(metavar)s"))


def log_arguments(logger, args):
    logger.info("Logging arguments:")
    logger.info("  log-level: '%s'", args.log_level or _LOG_LEVEL)
    logger.info("  debug: '%s'", args.debug)


def config(args):
    # Update the log-level
    if args.log_level:
        _STDOUT_HANDLER.setLevel(args.log_level.upper())
    # Direct debugging to a stream if specified
    if args.debug:
        _DEBUG_HANDLER.push(args.debug)


class Debug:
    """Debug file open/close wrapper for use with 'with'"""

    def __init__(self, logger, file_name):
        # XXX: Can logger argument be eliminated - log direct to
        # handler?
        self.logger = logger
        self.file_name = file_name
        self.debug_stream = None

    def __enter__(self):
        self.logger.debug("open debug logfile %s", self.file_name)
        self.debug_stream = open(self.file_name, "a")
        _DEBUG_HANDLER.push(self.debug_stream)
        self.logger.debug("starting debug log")

    def __exit__(self, type, value, traceback):
        # Restore debug logging before closing the debugfile.
        self.logger.debug("ending debug log")
        _DEBUG_HANDLER.pop()
        self.debug_stream.close()
        self.logger.debug("close debug logfile %s", self.file_name)


class DebugHandler(logging.Handler):

    def __init__(self):
        logging.Handler.__init__(self)
        self.stream_handlers = list()
        self.setLevel(NONE)

    def emit(self, record):
        for stream_handler in self.stream_handlers:
            stream_handler.emit(record)

    def push(self, stream):
        stream_handler = logging.StreamHandler(stream)
        stream_handler.setFormatter(self.formatter)
        self.stream_handlers.append(stream_handler)
        self.setLevel(DEBUG)

    def pop(self):
        stream_handler = self.stream_handlers.pop()
        stream_handler.flush()
        # This doesn't close the file; and probably does nothing.
        stream_handler.close()
        if not self.stream_handlers:
            self.setLevel(NONE)

    def flush(self):
        for stream_handler in self.stream_handlers:
            stream_handler.flush()


class Timer:
    """A stopwatch timer to count time since things started."""

    def __init__(self):
        self.start_times = list()
        self.__enter__()

    def __enter__(self):
        self.start_times.append(datetime.now())

    def __exit__(self, type, value, traceback):
        self.start_times.pop()

    def runtime(self, start_time, now):
        delta = now - start_time
        milliseconds = (delta.microseconds / 1000)
        seconds = delta.seconds % 60
        minutes = (delta.seconds // 60) % 60
        hours = (delta.seconds // 60 // 60) % 24
        days = delta.days
        if days > 0:
            # need days
            return str(delta)
        elif hours > 0:
            return "%d:%02d:%02d.%03d" % (hours, minutes, seconds, milliseconds)
        elif minutes > 0:
            return "%d:%02d.%03d" % (minutes, seconds, milliseconds)
        else:
            return "%d.%03d" % (seconds, milliseconds)

    def __str__(self):
        runtimes = ""
        now = datetime.now()
        for start_time in self.start_times:
            runtime = self.runtime(start_time, now)
            if runtimes:
                runtimes = runtimes + "/" + runtime
            else:
                runtimes = runtime
        return runtimes


class CustomMessageAdapter(logging.LoggerAdapter):

    def __init__(self, logger, prefix, **kwargs):
        self.kwargs = kwargs
        logging.LoggerAdapter.__init__(self, logger, kwargs)
        self.prefix = prefix

    def process(self, msg, kwargs):
        msg = (self.prefix % self.kwargs) + msg
        return msg, kwargs


__init__()
