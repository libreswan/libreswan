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

import logging
import sys
from fab import argutil

_STDOUT_HANDLER = None
_DEBUG_HANDLER = None
_LOG_LEVEL = "info"
_LOG_FORMAT = "%(name)s: %(message)s"
_DEBUG_FORMAT = "%(levelname)s %(name)s %(relativeCreated)d: %(message)s"

def __init__():

    global _STDOUT_HANDLER
    _STDOUT_HANDLER = logging.StreamHandler(sys.stdout)
    _STDOUT_HANDLER.setFormatter(logging.Formatter(_LOG_FORMAT))
    _STDOUT_HANDLER.setLevel(_LOG_LEVEL.upper())

    global _DEBUG_HANDLER
    _DEBUG_HANDLER = DebugHandler()
    _DEBUG_HANDLER.setFormatter(logging.Formatter(_DEBUG_FORMAT))

    # Force the root-logger to pass everything on to the handlers; and
    # then let the handlers filter just their log-records.
    logging.basicConfig(level=logging.NOTSET,
                        handlers=[_STDOUT_HANDLER, _DEBUG_HANDLER])


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

    return logger


def add_arguments(parser):
    log_format = _LOG_FORMAT.replace("%", "%%")
    group = parser.add_argument_group("Logging arguments",
                                      "Options for directing logging level and output")
    group.add_argument("--log-format",
                       help=("console log message format"
                             " (default: '" + log_format + "')"))
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
    logger.info("  log-format: '%s'", args.log_format or _LOG_FORMAT)
    logger.info("  log-level: '%s'", args.log_level or _LOG_LEVEL)
    logger.info("  debug: '%s'", args.debug)


def config(args):
    # Update the log-level
    if args.log_level:
        _STDOUT_HANDLER.setLevel(args.log_level.upper())
    if args.log_format:
        _STDOUT_HANDLER.setFormatter(logging.Formatter(args.log_format))
    # Direct debugging to a stream if specified
    if args.debug:
        debug(args.debug)


def debug(stream):
    return _DEBUG_HANDLER.stream(stream)


class DebugHandler(logging.Handler):

    NONE = 100

    def __init__(self):
        logging.Handler.__init__(self)
        self.stream_handler = None
        self.stream_output = None
        self.setLevel(self.NONE)

    def emit(self, record):
        if self.stream_handler:
            self.stream_handler.emit(record)

    def stream(self, stream):
        if self.stream_handler:
            self.stream_handler.flush()
            # This doesn't close the file; and probably does nothing.
            self.stream_handler.close()
            self.stream_handler = None
            self.setLevel(self.NONE)
        if stream:
            self.stream_handler = logging.StreamHandler(stream)
            self.stream_handler.setFormatter(self.formatter)
            self.setLevel(logging.DEBUG)
        # Finally, cross the streams ...
        self.stream_output, stream = stream, self.stream_output
        return stream

    def flush(self):
        if self.stream_handler:
            self.stream_handler.flush()

__init__()
