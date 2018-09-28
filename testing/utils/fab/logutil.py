# Some argument parsing functions.
#
# Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <https://www.gnu.org/licenses/gpl.txt>.
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
import threading
import os
from datetime import datetime

from fab import argutil
from fab import timing

# Avoid having code include both "logging" and "logutil" by
# re-exporting useful stuff here.  Good idea?  Perhaps.

ERROR = logging.ERROR
DEBUG = logging.DEBUG
INFO = logging.INFO
NONE = 100 # something large

class StreamProxy:
    def __init__(self):
        self.stream = None
    def write(self, record):
        self.stream.write(record)
    def flush(self):
        self.stream.flush()
    def delegate(self, stream):
        if self.stream:
            self.stream.flush()
        self.stream = stream
        return self

_DEFAULT_STREAM = None
_DEFAULT_HANDLER = None
_LOG_LEVEL = "info"

def __init__():

    # Start with things being sent to stderr, if it needs to switch do
    # that after argument parsing.
    global _DEFAULT_STREAM
    global _DEFAULT_HANDLER
    _DEFAULT_STREAM = StreamProxy().delegate(sys.stdout)
    _DEFAULT_HANDLER = logging.StreamHandler(_DEFAULT_STREAM)
    _DEFAULT_HANDLER.setFormatter(logging.Formatter("%(message)s"))
    _DEFAULT_HANDLER.setLevel(_LOG_LEVEL.upper())

    # Force the root-logger to pass everything on to STDERR; and then
    # let the handlers filter just their log-records.
    logging.basicConfig(level=logging.NOTSET, handlers=[_DEFAULT_HANDLER])


def getLogger(prefix, name=None, *suffixes):
    """Return the logger identified by <PREFIX><NAME> and SUFFIXES

    To, hopefully, make the logger's name more friendly, any module
    prefixes are stripped, and qualifying suffixes are appended.  For
    instance, "fab.shell" becomes "shell east" in log messages.

    XXX: An alternative construct might be: "fab.shell,east" becomes
    "fab.shell.east"; but "shell,east" becomes "shell east".

    """

    # name == __name__ == a.b.c == [0]="a.b" [1]="." [2]="c"
    logname = prefix
    if name:
        logname += name.rpartition(".")[2]
    for suffix in suffixes:
        if suffix:
            logname += " " + suffix
    logger = logging.getLogger(logname)

    # Log messages are first filtered by logger-level and then
    # filtered by handler-level.  This disables the logger filter so
    # that all messages get passed on to the handlers and their
    # filters.
    #
    # A more complicated alternative would be to set this, across all
    # loggers, dependent on --log-level and --debug.
    logger.setLevel(logging.NOTSET + 1)

    return CustomMessageAdapter(logger, prefix)


def add_arguments(parser):
    group = parser.add_argument_group("Logging arguments",
                                      "Options for directing logging level and output")
    group.add_argument("--log-level", default=_LOG_LEVEL,
                       help=("console log level (default: %(default)s)"))
    group.add_argument("--debug", "-d", default=None, metavar="FILE",
                       type=argutil.stdout_or_open_file,
                       help=("write a debug-level log to %(metavar)s"
                             "; specify '-' to write output to the screeen (stdout)"
                             "; append '+' to append-to instead of overwrite %(metavar)s"))


def log_arguments(logger, args):
    logger.info("Logging arguments:")
    logger.info("  log-level: '%s'", args.log_level)
    logger.info("  debug: '%s'", args.debug)


_DEBUG_STREAM = None
_DEBUG_FORMATTER = logging.Formatter("%(levelname)s %(message)s")

def config(args, stream):
    # Update the default stream
    _DEFAULT_STREAM.delegate(stream)
    _DEFAULT_HANDLER.setLevel(args.log_level.upper())
    # Direct debugging to a stream if specified
    if args.debug:
        _DEBUG_STREAM = logging.StreamHandler(args.debug)
        _DEBUG_STREAM.setFormatter(_DEBUG_FORMATTER)


class DebugHandler(logging.Handler):

    def __init__(self):
        logging.Handler.__init__(self)
        self.stream_handlers = list()
        self.setLevel(NONE)
        self.setFormatter(_DEBUG_FORMATTER)

    def emit(self, record):
        for stream_handler in self.stream_handlers:
            stream_handler.emit(record)
        if _DEBUG_STREAM:
            _DEBUG_STREAM.emit(record)

    def push(self, stream):
        stream_handler = logging.StreamHandler(stream)
        stream_handler.setFormatter(_DEBUG_FORMATTER)
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


class LogTime:
    """Log/time a with statement"""

    def __init__(self, logger_adapter, loglevel, action, timer):
        # XXX: Can logger argument be eliminated - log direct to
        # handler?
        self.logger_adapter = logger_adapter
        self.action = action
        self.timer = timer
        self.loglevel = loglevel

    def __enter__(self):
        timer = self.timer.__enter__()
        self.logger_adapter.log(self.loglevel, "start %s at %s",
                                self.action, timer.start)
        return timer

    def __exit__(self, type, value, traceback):
        self.timer.__exit__(type, value, traceback)
        self.logger_adapter.log(self.loglevel, "stop %s after %s",
                                self.action, self.timer)


class DebugTime(LogTime):
    """Push a new timer onto the timer stack, possibly sending output to DEBUGFILE"""

    def __init__(self, logger_adapter, logfile, loglevel, action, timer):
        super().__init__(logger_adapter=logger_adapter,
                         loglevel=loglevel, action=action,
                         timer=timer)
        self.logfile = logfile
        self.debug_stream = None

    def __enter__(self):
        if self.logfile:
            self.logger_adapter.debug("opening debug logfile '%s' at %s",
                                      self.logfile, datetime.now())
            self.debug_stream = open(self.logfile, "a")
            self.logger_adapter.pool.debug_handler.push(self.debug_stream)
            self.logger_adapter.debug("starting debug log at %s",
                                      datetime.now())
        timer = super().__enter__()
        self.logger_adapter.pool.runtimes.append(timer)
        return timer

    def __exit__(self, type, value, traceback):
        self.logger_adapter.pool.runtimes.pop()
        super().__exit__(type, value, traceback)
        if self.logfile:
            # Restore debug logging before closing the logfile.
            self.logger_adapter.debug("ending debug log at %s",
                                      datetime.now())
            self.logger_adapter.pool.debug_handler.pop()
            self.debug_stream.close()
            self.logger_adapter.debug("closed debug logfile '%s' at %s",
                                      self.logfile, datetime.now())


_LOG_POOL = {}

class LogPool:
    def __init__(self, prefix):
        self.name = prefix
        self.runtimes = [timing.Lapsed(timing.START_TIME)]
        self.debug_handler = DebugHandler()


class CustomMessageAdapter(logging.LoggerAdapter):

    def __init__(self, logger, prefix):
        logging.LoggerAdapter.__init__(self, logger, {prefix: prefix})
        if not prefix in _LOG_POOL:
            _LOG_POOL[prefix] = LogPool(prefix)
        self.pool = _LOG_POOL[prefix]
        self.logger.addHandler(self.pool.debug_handler)

    def process(self, msg, kwargs):
        runtimes = ""
        now = datetime.now()
        for runtime in self.pool.runtimes:
            if runtimes:
                runtimes += "/"
            runtimes += runtime.format(now)
        msg = "%s %s: %s" % (self.logger.name, runtimes, msg)
        return msg, kwargs

    def time(self, fmt, *args, loglevel=INFO, timer=None):
        return LogTime(self, loglevel=loglevel, action=(fmt % args),
                       timer=(timer or timing.Lapsed()))

    def debug_time(self, fmt, *args, logfile=None, loglevel=DEBUG, timer=None):
        return DebugTime(logger_adapter=self, logfile=logfile,
                         loglevel=loglevel, action=(fmt % args),
                         timer=(timer or timing.Lapsed()))

__init__()
