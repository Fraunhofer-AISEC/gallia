# SPDX-FileCopyrightText: 2019 Joseph R. Fox-Rabinovitz <jfoxrabinovitz at gmail dot com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Module is derived from:
# https://github.com/madphysicist/haggis/blob/e4e87e5aec9e473e765ea86ee170a8a7a4fca77c/src/haggis/logs.py


"""
Utilities for extending and configuring the logging framework.
This module is called ``logs`` instead of ``logging`` to avoid conflicts
with the builtin module. Since this module is a helper, it is expected
to be imported alongside the builtin module.
"""

import logging
import warnings


#: Default format string for the root logger. This string is set up by
#: the :py:func:`configure_logger` method.
_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

#: When adding a new logging level, with :py:func:`add_logging_level`,
#: silently keep the old level in case of conflict.
KEEP = "keep"


#: When adding a new logging level, with :py:func:`add_logging_level`,
#: keep the old level in case of conflict, and issue a warning.
KEEP_WARN = "keep-warn"


#: When adding a new logging level, with :py:func:`add_logging_level`,
#: silently overwrite any existing level in case of conflict.
OVERWRITE = "overwrite"


#: When adding a new logging level, with :py:func:`add_logging_level`,
#: overwrite any existing level in case of conflict, and issue a
#: warning.
OVERWRITE_WARN = "overwrite-warn"


#: When adding a new logging level, with :py:func:`add_logging_level`,
#: raise an error in case of conflict.
RAISE = "raise"


def add_logging_level(
    level_name,
    level_num,
    method_name=None,
    if_exists=KEEP,
    *,
    exc_info=False,
    stack_info=False,
):
    """
    Comprehensively add a new logging level to the :py:mod:`logging`
    module and the currently configured logging class.
    The `if_exists` parameter determines the behavior if the level
    name is already an attribute of the :py:mod:`logging` module or if
    the method name is already present, unless the attributes are
    configured to the exact values requested. Partial registration is
    considered a conflict. Even a complete registration will be
    overwritten if ``if_exists in (OVERWRITE, OVERWRITE_WARN)`` (without
    a warning of course).
    This function also accepts alternate default values for the keyword
    arguments ``exc_info`` and ``stack_info`` that are optional for
    every logging method. Setting alternate defaults allows levels for
    which exceptions or stacks are always logged.
    Parameters
    ----------
    level_name : str
        Becomes an attribute of the :py:mod:`logging` module with the
        value ``level_num``.
    level_num : int
        The numerical value of the new level.
    method_name : str
        The name of the convenience method for both :py:mod:`logging`
        itself and the class returned by
        :py:func:`logging.getLoggerClass` (usually just
        :py:class:`logging.Logger`). If ``method_name`` is not
        specified, ``level_name.lower()`` is used instead.
    if_exists : {KEEP, KEEP_WARN, OVERWRITE, OVERWRITE_WARN, RAISE}
        What to do if a level with `level_name` appears to already be
        registered in the :py:mod:`logging` module:
        :py:const:`KEEP`
            Silently keep the old level as-is.
        :py:const:`KEEP_WARN`
            Keep the old level around and issue a warning.
        :py:const:`OVERWRITE`
            Silently overwrite the old level.
        :py:const:`OVERWRITE_WARN`
            Overwrite the old level and issue a warning.
        :py:const:`RAISE`
            Raise an error.
        The default is :py:const:`KEEP_WARN`.
    exc_info : bool
        Default value for the ``exc_info`` parameter of the new method.
    stack_info : bool
        Default value for the ``stack_info`` parameter of the new
        method.
    Examples
    --------
    >>> add_logging_level('TRACE', logging.DEBUG - 5)
    >>> logging.getLogger(__name__).setLevel("TRACE")
    >>> logging.getLogger(__name__).trace('that worked')
    >>> logging.trace('so did this')
    >>> logging.TRACE
    5
    >>> add_logging_level('XTRACE', 2, exc_info=True)
    >>> logging.getLogger(__name__).setLevel(logging.XTRACE)
    >>> try:
    >>>     1 / 0
    >>> except:
    >>>     # This line will log the exception
    >>>     logging.getLogger(__name__).xtrace('that failed')
    >>>     # This one will not
    >>>     logging.xtrace('so did this', exc_info=False)
    The ``TRACE`` level can be added using :py:func:`add_trace_level`.
    """
    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def for_logger_class(self, message, *args, **kwargs):
        if self.isEnabledFor(level_num):
            kwargs.setdefault("exc_info", exc_info)
            kwargs.setdefault("stack_info", stack_info)
            self._log(level_num, message, args, **kwargs)

    def for_logging_module(*args, **kwargs):
        kwargs.setdefault("exc_info", exc_info)
        kwargs.setdefault("stack_info", stack_info)
        logging.log(level_num, *args, **kwargs)

    if not method_name:
        method_name = level_name.lower()

    # The number of items required for a full registration is 4
    items_found = 0
    # Items that are found complete but are not expected values
    items_conflict = 0

    # Lock because logger class and level name are queried and set
    logging._acquireLock()
    try:
        registered_num = logging.getLevelName(level_name)
        logger_class = logging.getLoggerClass()

        if registered_num != "Level " + level_name:
            items_found += 1
            if registered_num != level_num:
                if if_exists == RAISE:
                    # Technically this is not an attribute issue, but for
                    # consistency
                    raise AttributeError(
                        "Level {!r} already registered in logging "
                        "module".format(level_name)
                    )
                items_conflict += 1

        if hasattr(logging, level_name):
            items_found += 1
            if getattr(logging, level_name) != level_num:
                if if_exists == RAISE:
                    raise AttributeError(
                        "Level {!r} already defined in logging "
                        "module".format(level_name)
                    )
                items_conflict += 1

        if hasattr(logging, method_name):
            items_found += 1
            logging_method = getattr(logging, method_name)
            if (
                not callable(logging_method)
                or getattr(logging_method, "_original_name", None)
                != for_logging_module.__name__
            ):
                if if_exists == RAISE:
                    raise AttributeError(
                        "Function {!r} already defined in logging "
                        "module".format(method_name)
                    )
                items_conflict += 1

        if hasattr(logger_class, method_name):
            items_found += 1
            logger_method = getattr(logger_class, method_name)
            if (
                not callable(logger_method)
                or getattr(logger_method, "_original_name", None)
                != for_logger_class.__name__
            ):
                if if_exists == RAISE:
                    raise AttributeError(
                        "Method {!r} already defined in logger "
                        "class".format(method_name)
                    )
                items_conflict += 1

        if items_found > 0:
            # items_found >= items_conflict always
            if (items_conflict or items_found < 4) and if_exists in (
                KEEP_WARN,
                OVERWRITE_WARN,
            ):
                action = "Keeping" if if_exists == KEEP_WARN else "Overwriting"
                if items_conflict:
                    problem = "has conflicting definition"
                    items = items_conflict
                else:
                    problem = "is partially configured"
                    items = items_found
                warnings.warn(
                    "Logging level {!r} {} already ({}/4 items): {}".format(
                        level_name, problem, items, action
                    )
                )

            if if_exists in (KEEP, KEEP_WARN):
                return

        # Make sure the method names are set to sensible values, but
        # preserve the names of the old methods for future verification.
        for_logger_class._original_name = for_logger_class.__name__
        for_logger_class.__name__ = method_name
        for_logging_module._original_name = for_logging_module.__name__
        for_logging_module.__name__ = method_name

        # Actually add the new level
        logging.addLevelName(level_num, level_name)
        setattr(logging, level_name, level_num)
        setattr(logger_class, method_name, for_logger_class)
        setattr(logging, method_name, for_logging_module)
    finally:
        logging._releaseLock()


def _get_formatter(format=None):
    """
    Retrieve a consistent :py:class:`~logging.Formatter` object based
    on the input format.
    If `format` is already a :py:class:`~logging.Formatter`, return it
    as-is. If :py:obj:`None`, use a default format string. Otherwise, it
    is expected to be a string that initializes a proper
    :py:class:`~logging.Formatter` instance.
    """
    if isinstance(format, logging.Formatter):
        return format
    if format is None:
        format = _format
    return logging.Formatter(format)
