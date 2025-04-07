# Some argument parsing functions.
#
# Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
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


def getLogger(*names, module=None):

    # name == __name__ == a.b.c == [0]="a.b" [1]="." [2]="c"
    sep = ""
    logname = ""
    for name in names:
        if name:
            logname += sep
            logname += name
            sep = " "
    if module:
        logname += " "
        logname += module.rpartition(".")[2]
    logger = logging.getLogger(logname)

    # Log messages are first filtered by logger-level and then
    # filtered by handler-level.  This disables the logger filter so
    # that all messages get passed on to the handlers and their
    # filters.
    #
    # A more complicated alternative would be to set this, across all
    # loggers, dependent on --log-level and --debug.
    logger.setLevel(logging.NOTSET + 1)

    return CustomMessageAdapter(logger, logname)


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

class LogTimeWithContext:
    """Push a new timer onto the log_timer stack"""

    def __init__(self, logger_adapter, loglevel, action):
        self.logger_adapter = logger_adapter
        self.action = action
        self.timer = timing.Lapsed()
        self.loglevel = loglevel

    def __enter__(self):
        timer = self.timer.__enter__()
        self.logger_adapter.log(self.loglevel, "start %s at %s",
                                self.action, timer.start)
        return timer

    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.timer.__exit__(exception_type, exception_value, exception_traceback)
        self.logger_adapter.log(self.loglevel, "stop %s after %s",
                                self.action, self.timer)


class DebugTimeWithContext(LogTimeWithContext):
    """Push a new timer onto the debug_timer stack, possibly sending output to DEBUGFILE"""

    def __init__(self, logger_adapter, logfile, loglevel, action):
        super().__init__(logger_adapter=logger_adapter,
                         loglevel=loglevel, action=action)
        self.logfile = logfile
        self.debug_stream = None

    def __enter__(self):
        if self.logfile:
            self.logger_adapter.debug("opening debug logfile '%s' at %s",
                                      self.logfile, datetime.now())
            self.debug_stream = open(self.logfile, "a")
            self.logger_adapter.debug_handler.push(self.debug_stream)
            self.logger_adapter.debug("starting debug log at %s",
                                      datetime.now())
        timer = super().__enter__()
        self.logger_adapter.runtimes.append(timer)
        return timer

    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.logger_adapter.runtimes.pop()
        super().__exit__(exception_type, exception_value, exception_traceback)
        if self.logfile:
            # Restore debug logging before closing the logfile.
            self.logger_adapter.debug("ending debug log at %s",
                                      datetime.now())
            self.logger_adapter.debug_handler.pop()
            self.debug_stream.close()
            self.logger_adapter.debug("closed debug logfile '%s' at %s",
                                      self.logfile, datetime.now())

class CustomMessageAdapter(logging.LoggerAdapter):

    def __init__(self, logger, prefix, runtimes=None):
        logging.LoggerAdapter.__init__(self, logger, {prefix: prefix})
        self.debug_handler = DebugHandler()
        self.logger.addHandler(self.debug_handler)
        self.runtimes = runtimes or [timing.Lapsed()]
        self.prefix = prefix

    def process(self, msg, kwargs):
        now = datetime.now()
        runtimes = '/'.join(r.format(now) for r in self.runtimes)
        msg = "%s %s: %s" % (self.prefix, runtimes, msg)
        return msg, kwargs

    def time(self, fmt, *args, loglevel=INFO):
        return LogTimeWithContext(logger_adapter=self, loglevel=loglevel,
                                  action=(fmt % args))

    def debug_time(self, fmt, *args, logfile=None, loglevel=DEBUG):
        return DebugTimeWithContext(logger_adapter=self, logfile=logfile,
                                    loglevel=loglevel, action=(fmt % args))

    def nest(self, prefix):
        return CustomMessageAdapter(self.logger, prefix, self.runtimes)

__init__()
