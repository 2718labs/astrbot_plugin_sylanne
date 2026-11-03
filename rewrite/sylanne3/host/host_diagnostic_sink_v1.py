"""AstrBot SDK logger sink installed by the plugin process.

Plugin-market rules require plugin logging to go through
``from astrbot.api import logger``. The same runtime modules also load in the
independently installed Authority service, where the AstrBot SDK is absent, so
they emit through ``sylanne3.diagnostic_channel_v1``. This adapter is the host
process's formal sink: every channel record lands on the SDK plugin logger.

Import this module only from the AstrBot host process.
"""
from __future__ import annotations

from astrbot.api import logger as _sdk_logger

from ..diagnostic_channel_v1 import DiagnosticSinkV1, render_diagnostic_message_v1

_LEVEL_TO_SDK_METHOD = {
    "debug": "debug",
    "info": "info",
    "warning": "warning",
    "error": "error",
    # ``exception`` keeps the truth: ERROR severity plus the captured traceback.
    "exception": "error",
}


class AstrBotDiagnosticSinkV1(DiagnosticSinkV1):
    """Route channel records to ``astrbot.api.logger`` with module provenance."""

    __slots__ = ("_logger",)

    def __init__(self, sdk_logger=_sdk_logger):
        if sdk_logger is None or not callable(getattr(sdk_logger, "warning", None)):
            raise TypeError("AstrBot diagnostic sink requires the SDK plugin logger")
        self._logger = sdk_logger

    def emit(self, level, message, args, *, module, exc_text):
        text = render_diagnostic_message_v1(message, args)
        if module:
            text = "[" + module + "] " + text
        if exc_text:
            text = text + "\n" + exc_text
        method = getattr(self._logger, _LEVEL_TO_SDK_METHOD[level])
        method(text)
