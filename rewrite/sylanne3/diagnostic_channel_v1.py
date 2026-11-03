"""Neutral diagnostic channel shared by the AstrBot host and the Authority service.

The shipped Sylanne runtime is imported by two different processes:

* the AstrBot plugin host, which must emit through the AstrBot SDK logger
  (``from astrbot.api import logger``) to satisfy the plugin-market logging
  requirement, and
* the independently installed Authority service, which is deployed without
  AstrBot and therefore cannot import the SDK.

Shared runtime modules are imported by both, so they must not import ``logging``
(rejected by the plugin market) and must not import ``astrbot`` (absent in the
Authority deployment). They emit records here instead. Each process wires its
own formal sink at its own process boundary:

* the AstrBot host installs ``AstrBotDiagnosticSinkV1`` in the plugin entry
  ``main.py``, immediately after importing the SDK logger;
* the Authority service installs the trusted-service stderr sink in
  ``AuthorityDaemon.start`` and the maintenance console entry. That stderr
  stream is the installed service's journald/systemd capture, which is the same
  channel the previous stdlib logger reached through ``lastResort``.

This module is deliberately not a logging fallback: it contains no stdlib
logging import and no surrogate logger that hides failures. The default sink is
the trusted-service stderr sink so a record emitted before a process wires its
sink is not lost, and both production processes wire explicitly. The default
threshold keeps the previous effective visibility (WARNING and above); the
``debug``/``info`` channel methods remain available for sinks that lower it.
"""
from __future__ import annotations

import sys
import threading
import traceback

_LEVEL_VALUES = {"debug": 10, "info": 20, "warning": 30, "error": 40, "exception": 40}
_DEFAULT_MINIMUM_LEVEL = "warning"
_state_lock = threading.Lock()
_installed_sink = None
_minimum_level = _DEFAULT_MINIMUM_LEVEL


class DiagnosticSinkV1:
    """Closed sink contract: one formal diagnostic destination per process."""

    __slots__ = ()

    def emit(self, level, message, args, *, module, exc_text):
        raise NotImplementedError


def render_diagnostic_message_v1(message, args):
    """Render one record body without letting a format mistake hide the record."""
    if not isinstance(message, str):
        message = str(message)
    if not args:
        return message
    try:
        return message % args
    except (TypeError, ValueError):
        return message + " " + " ".join(repr(value) for value in args)


class StderrDiagnosticSinkV1(DiagnosticSinkV1):
    """Trusted-service destination: the installed service's stderr capture.

    The Authority and maintenance-console processes are started by the OS
    service supervisor, so stderr is the formal journald/systemd log stream.
    The line format intentionally matches the previous stdlib ``lastResort``
    output: the rendered message, an optional traceback, one trailing newline.
    """

    __slots__ = ("_stream",)

    def __init__(self, stream=None):
        self._stream = stream

    def emit(self, level, message, args, *, module, exc_text):
        text = render_diagnostic_message_v1(message, args)
        if exc_text:
            text = text + "\n" + exc_text
        stream = self._stream if self._stream is not None else sys.stderr
        try:
            stream.write(text if text.endswith("\n") else text + "\n")
            stream.flush()
        except (OSError, ValueError):
            # A closed service stderr (for example during shutdown) must not turn
            # the business refusal being reported into a different failure.
            return None


_DEFAULT_SINK = StderrDiagnosticSinkV1()


class DiagnosticChannelV1:
    """Module-qualified emitter routed to the process's installed sink."""

    __slots__ = ("_module",)

    def __init__(self, module):
        self._module = module

    def debug(self, message, *args, **kwargs):
        _emit_diagnostic_v1("debug", self._module, message, args, kwargs)

    def info(self, message, *args, **kwargs):
        _emit_diagnostic_v1("info", self._module, message, args, kwargs)

    def warning(self, message, *args, **kwargs):
        _emit_diagnostic_v1("warning", self._module, message, args, kwargs)

    def error(self, message, *args, **kwargs):
        _emit_diagnostic_v1("error", self._module, message, args, kwargs)

    def exception(self, message, *args, **kwargs):
        kwargs.setdefault("exc_info", True)
        _emit_diagnostic_v1("exception", self._module, message, args, kwargs)


def diagnostic_channel_v1(module):
    """Return the emitter for one runtime module name (usually ``__name__``)."""
    if not isinstance(module, str) or not module:
        raise ValueError("diagnostic channel requires the emitting module name")
    return DiagnosticChannelV1(module)


def install_diagnostic_sink_v1(sink, *, minimum_level=None, replace=True):
    """Wire the process's formal diagnostic sink.

    ``replace=False`` lets a service boundary assert its own destination without
    overriding a sink the embedding process already installed. The returned
    value is the sink now in effect.
    """
    global _installed_sink, _minimum_level
    if not callable(getattr(sink, "emit", None)):
        raise TypeError("diagnostic sink must provide emit(level, message, args, *, module, exc_text)")
    level = _DEFAULT_MINIMUM_LEVEL if minimum_level is None else minimum_level
    if level not in _LEVEL_VALUES:
        raise ValueError("unknown diagnostic minimum level")
    with _state_lock:
        if _installed_sink is not None and not replace:
            return _installed_sink
        _installed_sink = sink
        _minimum_level = level
    return sink


def current_diagnostic_sink_v1():
    """Return the sink now in effect without changing process wiring."""
    with _state_lock:
        return _installed_sink if _installed_sink is not None else _DEFAULT_SINK


def _exception_text_v1(exc_info):
    if not exc_info:
        return None
    if exc_info is True:
        text = traceback.format_exc()
    elif isinstance(exc_info, tuple) and len(exc_info) == 3:
        text = "".join(traceback.format_exception(*exc_info))
    else:
        raise TypeError("exc_info must be True or a three-item exception tuple")
    stripped = text.strip()
    if not stripped or stripped == "NoneType: None":
        return None
    return text.rstrip("\n")


def _emit_diagnostic_v1(level, module, message, args, kwargs):
    exc_info = kwargs.pop("exc_info", None)
    if kwargs:
        raise TypeError("unsupported diagnostic keyword arguments: " + ", ".join(sorted(kwargs)))
    with _state_lock:
        sink = _installed_sink if _installed_sink is not None else _DEFAULT_SINK
        minimum = _minimum_level
    if _LEVEL_VALUES[level] < _LEVEL_VALUES[minimum]:
        return None
    exc_text = _exception_text_v1(exc_info)
    sink.emit(level, message, args, module=module, exc_text=exc_text)
    return None
