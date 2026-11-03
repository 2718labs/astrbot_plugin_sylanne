"""Shared exact typed canonical stream with live-frame high-water accounting."""
from dataclasses import fields, is_dataclass
from enum import Enum
import sys
from ..graph_types import AtomKey
from .owner_material_source_storage_v3 import CanonicalValueStreamV3


class RuntimeCanonicalStreamV3(CanonicalValueStreamV3):
    """Original canonical algebra with a reserved live-frame high-water mark."""
    def __init__(self, value, operation):
        self.operation = operation
        self._active = set()
        self.live_bytes = self.peak_bytes = 0
        super().__init__(value)

    def _enter_frame_v3(self, size):
        wanted = self.live_bytes + size
        if wanted > self.peak_bytes:
            self.operation.retain(wanted - self.peak_bytes)
            self.peak_bytes = wanted
        self.live_bytes = wanted

    def _value(self, value, meter_getter=None):
        if value is None or type(value) in (str, bool, int, float):
            yield from CanonicalValueStreamV3._value(value, meter_getter)
            return
        if isinstance(value, Enum):
            yield from self._value(value.value, meter_getter)
            return
        frame = 0
        marker = None
        try:
            if isinstance(value, AtomKey):
                # Reserve the actual token construction and nested wrapper while
                # this frame is live; sibling keys reuse the same arena.
                size = 4096 + 24 * sum(len(part) for part in (value.owner.kind,
                    value.owner.bot, value.owner.persona, value.owner.subject or "",
                    value.type_name, value.name))
                self._enter_frame_v3(size)
                frame += size
                yield from self._value({"$type": "AtomKey", "token": value.token}, meter_getter)
                return
            typed = is_dataclass(value) and not isinstance(value, type)
            if not typed and type(value) not in (dict, list, tuple):
                raise TypeError(f"unsupported canonical value: {type(value).__name__}")
            actual_marker = id(value)
            if actual_marker in self._active:
                raise ValueError("cyclic canonical value")
            self._enter_frame_v3(512)
            frame += 512
            self._active.add(actual_marker)
            marker = actual_marker
            if typed:
                names = fields(value)
                size = 1024 + len(names) * 192
                self._enter_frame_v3(size)
                frame += size
                value = {"$type": type(value).__module__ + "." + type(value).__qualname__,
                    **{field.name: getattr(value, field.name) for field in names}}
            if type(value) is dict:
                size = sys.getsizeof(value) + len(value) * 16 + 512
                self._enter_frame_v3(size)
                frame += size
                if any(not isinstance(key, str) for key in value):
                    raise TypeError("canonical object keys must be strings")
                names = sorted(value)
                yield b"{"
                for index, key in enumerate(names):
                    if index:
                        yield b","
                    yield from self._quoted(key, meter_getter)
                    yield b":"
                    yield from self._value(value[key], meter_getter)
                yield b"}"
            else:
                yield b"["
                for index, item in enumerate(value):
                    if index:
                        yield b","
                    yield from self._value(item, meter_getter)
                yield b"]"
        finally:
            if marker is not None:
                self._active.remove(marker)
            self.live_bytes -= frame
