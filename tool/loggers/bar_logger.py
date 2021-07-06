import progressbar
from enum import Enum
import time
import sys
from datetime import datetime


class LogLevel(Enum):
    DEBUG = 'DEBUG'
    INFO = 'INFO'
    WARNING = 'WARNING'
    ERROR = 'ERROR'


class BColors:
    HEADER = '\033[95m'
    DEBUG = '\033[34m'
    INFO = "\033[32m"
    WARNING = '\033[33m'
    FAIL = '\033[31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class BarLogger:
    """
        Karonte Bar Logger
    """

    def __init__(self, name_logger, level_logger):
        """
        Initialization method

        :param name_logger: name of the logger
        :param level_logger: level of the logger (DEBUG, INFO, WARNING, ERROR)
        """

        self._log_level = LogLevel(level_logger)
        self._tot_elaborations = 1
        self._completed_elaborations = 0
        self._name_logger = name_logger
        self._bar = None
        self._ETC = 'Unknown'

    def set_etc(self, sec_etc):
        """
        Set the estimated time to completion in seconds

        :param sec_etc: time to completion
        :return: None
        """

        self._ETC = datetime.fromtimestamp(sec_etc).strftime("%I:%M:%S")

    def set_tot_elaborations(self, tot_elaborations):
        """
        Set the total number of elaborations

        :param tot_elaborations: total number of elaborations
        :return: None
        """

        widgets = [
            progressbar.Percentage(),
            ' (', progressbar.SimpleProgress(), ') ',

            progressbar.Bar(),
            progressbar.Timer(),
            ' ETC: ', self._ETC, ' '
        ]
        self._bar = progressbar.ProgressBar(redirect_stderr=True, max_value=tot_elaborations, widgets=widgets)
        self._bar.start()
        self.reset_completed_elaborations()
        self._tot_elaborations = tot_elaborations

    def new_elaboration(self):
        """
        Next elaboration

        :return: None
        """

        self.completed_elaborations(1)

    def completed_elaborations(self, n):
        """
        Set completed elaborations

        :param n: number of elaborations completed
        :return: None
        """

        self._completed_elaborations += n
        self._update_bar()

    def reset_completed_elaborations(self):
        """
        Set completed elaborations

        :param n: number of elaborations completed
        :return: None
        """

        self._completed_elaborations = 0
        self._update_bar()

    def _print_it(self, type_m, color, msg, *kargs):
        """
        Log it!

        :param type_m: message type
        :param color: color
        :param msg: message
        :param kargs: kargs
        :return: None
        """

        ts = time.strftime("%Y-%m-%d %H:%M")

        type_str_fmt = LogLevel.DEBUG
        if type_m == LogLevel.DEBUG:
            type_str_fmt = 'DEBUG     | '
        if type_m == LogLevel.INFO:
            type_str_fmt = 'INFO      | '
        if type_m == LogLevel.WARNING:
            type_str_fmt = 'WARNING   | '
        if type_m == LogLevel.ERROR:
            type_str_fmt = 'ERROR     | '

        header = type_str_fmt + str(ts) + ' | ' + self._name_logger + '  |  '
        sys.stderr.write(header + color + msg.replace('%s', '{}').format(*kargs) + BColors.ENDC + '\n')

    def _update_bar(self):
        """
        Update the bar

        :return: None
        """

        if self._bar:
            try:
                self._bar.update(self._completed_elaborations)
            except:
                pass

    def error(self, msg, *kargs):
        """
        Error message

        :param msg: message
        :param kargs:  kargs
        :return: None
        """

        try:
            self._print_it(LogLevel.ERROR, BColors.FAIL, msg, *kargs)
            self._update_bar()
        except:
            pass

    def warning(self, msg, *kargs):
        """
        Warning message

        :param msg: message
        :param kargs:  kargs
        :return: None
        """

        try:
            if self._log_level in (LogLevel.WARNING, LogLevel.INFO, LogLevel.DEBUG):
                self._print_it(LogLevel.WARNING, BColors.WARNING, msg, *kargs)
            self._update_bar()
        except:
            pass

    def info(self, msg, *kargs):
        """
        Info message

        :param msg: message
        :param kargs:  kargs
        :return: None
        """

        try:
            if self._log_level in (LogLevel.INFO, LogLevel.DEBUG):
                self._print_it(LogLevel.INFO, BColors.INFO, msg, *kargs)
            self._update_bar()
        except:
            pass

    def debug(self, msg, *kargs):
        """
        Debug message

        :param msg: message
        :param kargs:  kargs
        :return: None
        """

        try:
            if self._log_level in (LogLevel.DEBUG,):
                self._print_it(LogLevel.DEBUG, BColors.DEBUG, msg, *kargs)
            self._update_bar()
        except:
            pass

    def complete(self):
        """
        Set the bar to complete
        :return: None
        """

        try:
            print(self._completed_elaborations)
            self._completed_elaborations = self._tot_elaborations
            self._update_bar()
            if self._bar:
                self._bar.finish()
            progressbar.streams.flush()
        except:
            pass
