# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import json
import logging
from datetime import date, datetime


class DateTimeEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, (datetime, date)):
            serial = o.isoformat()
            return serial
        raise TypeError("Type %s not serializable" % type(o))


class Logger(object):
    def __init__(self, loglevel="warning"):
        """Initializes logging"""
        self.config(loglevel=loglevel)

    def config(self, loglevel="warning"):
        loglevel = logging.getLevelName(loglevel.upper())
        mainlogger = logging.getLogger()
        mainlogger.setLevel(loglevel)

        logfmt = "%(levelname)s %(message)s\n"
        if len(mainlogger.handlers) == 0:
            mainlogger.addHandler(logging.StreamHandler())
        mainlogger.handlers[0].setFormatter(logging.Formatter(logfmt))
        self.log = logging.LoggerAdapter(mainlogger, {})

    def _format(self, message):
        """formats log message in json

        Args:
        message (str): log message, can be a dict, list, string, or json blob
        """
        try:
            message = json.loads(message)
        except Exception:
            pass
        try:
            return json.dumps(message, indent=4, cls=DateTimeEncoder)
        except Exception:
            return json.dumps(str(message))

    def debug(self, message, **kwargs):
        """wrapper for logging.debug call"""
        self.log.debug(self._format(message), **kwargs)

    def info(self, message, **kwargs):
        """wrapper for logging.info call"""
        self.log.info(self._format(message), **kwargs)

    def warning(self, message, **kwargs):
        """wrapper for logging.warning call"""
        self.log.warning(self._format(message), **kwargs)

    def error(self, message, **kwargs):
        """wrapper for logging.error call"""
        self.log.error(self._format(message), **kwargs)

    def critical(self, message, **kwargs):
        """wrapper for logging.critical call"""
        self.log.critical(self._format(message), **kwargs)

    def exception(self, message, **kwargs):
        """wrapper for logging.exception call"""
        self.log.exception(self._format(message), **kwargs)
