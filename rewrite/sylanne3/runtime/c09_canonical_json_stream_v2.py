"""Bounded incremental parser for the installed canonical UTF-8 JSON byte format."""
from __future__ import annotations

from dataclasses import dataclass
import codecs
import hashlib
import json
import math
from typing import Callable


MAX_FRAGMENT_BYTES_V2 = 16_384
MAX_DEPTH_V2 = 64
MAX_KEY_BYTES_V2 = 1_024
MAX_FLOAT_LEXEME_BYTES_V2 = 128
_SHORT_ESCAPES = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
_SHORT_CONTROL_CODEPOINTS = {8, 9, 10, 12, 13}
_HEX_LOWER = b"0123456789abcdef"


class C09CanonicalJSONUnsupportedV2(ValueError):
    """The requested parser profile cannot safely represent this input."""


@dataclass(frozen=True, slots=True)
class C09JSONEventV2:
    kind: str
    path: tuple[str | int, ...]
    start_offset: int
    end_offset: int
    raw: bytes = b""
    key: str | None = None
    scalar_kind: str | None = None


@dataclass(frozen=True, slots=True)
class C09JSONStreamProgressV2:
    consumed_bytes: int
    byte_count: int
    need_more: bool


@dataclass(frozen=True, slots=True)
class C09JSONStreamResultV2:
    byte_count: int
    sha256: str


@dataclass(slots=True)
class _ContainerV2:
    kind: str
    path: tuple[str | int, ...]
    state: str
    previous_key: str | None = None
    current_key: str | None = None
    index: int = 0


class C09CanonicalJSONStreamV2:
    """Parse canonical JSON as bounded byte fragments and emit events synchronously.

    `scalar_start.raw` is the first source byte and overlaps the first
    `scalar_chunk`; consumers use offsets for navigation and the stream digest
    for whole-input integrity. Chunks carry the scalar's exact original bytes,
    including string quotes and escapes. Commas and colons are parser syntax,
    not events. No event list or complete JSON value is retained here.
    """

    __slots__ = (
        "ensure_ascii", "max_depth", "max_key_bytes", "_stack", "_root_done",
        "_byte_count", "_sha256", "_finished", "_failed", "_string",
        "_literal", "_number", "_active_scalar", "_emit_callback", "_feeding",
    )

    def __init__(self, *, ensure_ascii: bool = True, max_depth: int = 64,
                 max_key_bytes: int = 1_024):
        if type(ensure_ascii) is not bool:
            raise TypeError("ensure_ascii must be an exact bool")
        if type(max_depth) is not int or not 1 <= max_depth <= MAX_DEPTH_V2:
            raise C09CanonicalJSONUnsupportedV2("canonical JSON depth exceeds the installed bound")
        if type(max_key_bytes) is not int or not 0 <= max_key_bytes <= MAX_KEY_BYTES_V2:
            raise C09CanonicalJSONUnsupportedV2("canonical object key bound exceeds the installed profile")
        self.ensure_ascii = ensure_ascii
        self.max_depth = max_depth
        self.max_key_bytes = max_key_bytes
        self._stack: list[_ContainerV2] = []
        self._root_done = False
        self._byte_count = 0
        self._sha256 = hashlib.sha256()
        self._finished = False
        self._failed = False
        self._string = None
        self._literal = None
        self._number = None
        self._active_scalar = None
        self._emit_callback = None
        self._feeding = False

    def copy(self):
        """Private quantum snapshot, including real SHA and incremental UTF-8 state."""
        from copy import deepcopy
        if self._feeding:
            raise RuntimeError('canonical parser cannot be copied during a live emit callback')
        result=type(self)(ensure_ascii=self.ensure_ascii,max_depth=self.max_depth,max_key_bytes=self.max_key_bytes)
        for name in self.__slots__:
            if name=='_emit_callback':
                result._emit_callback=self._emit_callback
            elif name=='_sha256':
                result._sha256=self._sha256.copy()
            elif name=='_string' and self._string is not None:
                state={key:deepcopy(value) for key,value in self._string.items() if key!='decoder'}
                decoder=self._string['decoder']
                if decoder is None:
                    state['decoder']=None
                else:
                    state['decoder']=codecs.getincrementaldecoder('utf-8')('strict')
                    state['decoder'].setstate(decoder.getstate())
                result._string=state
            else:
                setattr(result,name,deepcopy(getattr(self,name)))
        return result

    @property
    def byte_count(self) -> int:
        return self._byte_count

    def _emit(self, emit: Callable[[C09JSONEventV2], None], kind: str,
              path: tuple[str | int, ...], start: int, end: int, *,
              raw: bytes = b"", key: str | None = None,
              scalar_kind: str | None = None) -> None:
        emit(C09JSONEventV2(kind, path, start, end, raw, key, scalar_kind))

    def _value_path(self) -> tuple[str | int, ...]:
        if not self._stack:
            if self._root_done:
                raise ValueError("canonical JSON contains trailing data")
            return ()
        frame = self._stack[-1]
        if frame.kind == "object" and frame.state == "value" and frame.current_key is not None:
            return frame.path + (frame.current_key,)
        if frame.kind == "array" and frame.state in {"value_or_end", "value_required"}:
            return frame.path + (frame.index,)
        raise ValueError("canonical JSON value appears outside its object/array slot")

    def _complete_value(self) -> None:
        if not self._stack:
            if self._root_done:
                raise ValueError("canonical JSON has more than one root value")
            self._root_done = True
            return
        frame = self._stack[-1]
        if frame.kind == "object" and frame.state == "value":
            frame.current_key = None
            frame.state = "comma_or_end"
            return
        if frame.kind == "array" and frame.state in {"value_or_end", "value_required"}:
            frame.index += 1
            frame.state = "comma_or_end"
            return
        raise ValueError("canonical JSON value ended outside its object/array slot")

    def _begin_scalar(self, emit, kind: str, path, start: int, first: int) -> None:
        self._active_scalar = {"kind": kind, "path": path, "start": start}
        self._emit(emit, "scalar_start", path, start, start + 1,
                   raw=bytes((first,)), scalar_kind=kind)

    def _chunk(self, fragment: bytes, start_index: int | None, end_index: int,
               base: int, emit) -> None:
        if start_index is None or end_index <= start_index:
            return
        active = self._active_scalar
        if active is None:
            raise ValueError("canonical scalar chunk lost its source token")
        self._emit(emit, "scalar_chunk", active["path"], base + start_index,
                   base + end_index, raw=fragment[start_index:end_index],
                   scalar_kind=active["kind"])

    def _end_scalar(self, emit, end_offset: int) -> None:
        active = self._active_scalar
        if active is None:
            raise ValueError("canonical scalar ended without a start")
        self._emit(emit, "scalar_end", active["path"], active["start"],
                   end_offset, scalar_kind=active["kind"])
        self._active_scalar = None
        self._complete_value()

    def _begin_string(self, *, mode: str, path, start: int) -> None:
        self._string = {
            "mode": mode, "path": path, "start": start, "escape": False,
            "unicode_digits": None, "unicode_value": 0, "unicode_count": 0,
            "decoder": None if self.ensure_ascii else codecs.getincrementaldecoder("utf-8")("strict"),
            "key_parts": [], "key_bytes": 0, "pending_high": None,
            "key_raw": bytearray(),
        }

    def _append_key_text(self, text: str) -> None:
        state = self._string
        if state is None or state["mode"] != "key":
            return
        state["key_bytes"] += len(text.encode("utf-8", "surrogatepass"))
        if state["key_bytes"] > self.max_key_bytes:
            raise C09CanonicalJSONUnsupportedV2("canonical object key exceeds the installed byte bound")
        state["key_parts"].append(text)

    def _append_key_codepoint(self, codepoint: int) -> None:
        state = self._string
        if state is None or state["mode"] != "key":
            return
        pending = state["pending_high"]
        if pending is not None:
            if 0xDC00 <= codepoint <= 0xDFFF:
                combined = 0x10000 + ((pending - 0xD800) << 10) + (codepoint - 0xDC00)
                state["pending_high"] = None
                self._append_key_text(chr(combined))
                return
            state["pending_high"] = None
            self._append_key_text(chr(pending))
        if 0xD800 <= codepoint <= 0xDBFF:
            state["pending_high"] = codepoint
        else:
            self._append_key_text(chr(codepoint))

    def _canonical_unicode_escape(self, codepoint: int) -> None:
        if self.ensure_ascii:
            if 0x20 <= codepoint <= 0x7E or codepoint in _SHORT_CONTROL_CODEPOINTS:
                raise ValueError("canonical JSON uses an unnecessary Unicode escape")
            return
        if 0xD800 <= codepoint <= 0xDFFF:
            raise C09CanonicalJSONUnsupportedV2("ensure_ascii=False cannot encode a surrogate in UTF-8")
        if codepoint >= 0x20 or codepoint in _SHORT_CONTROL_CODEPOINTS:
            raise ValueError("ensure_ascii=False canonical JSON uses an unnecessary Unicode escape")

    def _append_decoded_codepoint(self, codepoint: int) -> None:
        state = self._string
        if state is not None and state["mode"] == "key":
            self._append_key_codepoint(codepoint)

    def _consume_string_byte(self, byte: int, offset: int) -> bool:
        """Consume one non-opening-quote string byte; return true on close."""
        state = self._string
        if state is None:
            raise ValueError("canonical string state is absent")
        digits = state["unicode_digits"]
        if digits is not None:
            if byte not in _HEX_LOWER:
                raise ValueError("canonical Unicode escape must use four lowercase hexadecimal digits")
            value = int(chr(byte), 16)
            state["unicode_value"] = (state["unicode_value"] << 4) | value
            state["unicode_count"] += 1
            digits.append(byte)
            if state["unicode_count"] == 4:
                codepoint = state["unicode_value"]
                self._canonical_unicode_escape(codepoint)
                self._append_decoded_codepoint(codepoint)
                state["unicode_digits"] = None
                state["unicode_value"] = 0
                state["unicode_count"] = 0
            return False

        if state["escape"]:
            state["escape"] = False
            if byte == ord("u"):
                state["unicode_digits"] = bytearray()
                return False
            if byte == ord('"'):
                self._append_decoded_codepoint(ord('"'))
                return False
            if byte == ord("\\"):
                self._append_decoded_codepoint(ord("\\"))
                return False
            if byte == ord("/"):
                raise ValueError("canonical JSON does not escape slash")
            escape = _SHORT_ESCAPES.get(chr(byte))
            if escape is None:
                raise ValueError("canonical JSON string has an invalid escape")
            self._append_decoded_codepoint(ord(escape))
            return False

        if byte == ord('"'):
            decoder = state["decoder"]
            if decoder is not None:
                tail = decoder.decode(b"", final=True)
                if tail:
                    for char in tail:
                        self._append_decoded_codepoint(ord(char))
            if state["pending_high"] is not None:
                self._append_key_text(chr(state["pending_high"]))
                state["pending_high"] = None
            if state["mode"] != "key":
                self._string = None
            return True
        if byte == ord("\\"):
            decoder = state["decoder"]
            if decoder is not None and decoder.getstate()[0]:
                raise ValueError("canonical JSON string contains incomplete UTF-8 before escape")
            state["escape"] = True
            return False
        if byte < 0x20:
            raise ValueError("canonical JSON contains an unescaped control byte")
        if self.ensure_ascii:
            if byte >= 0x7F:
                raise ValueError("ensure_ascii=True canonical JSON must escape non-ASCII bytes")
            self._append_decoded_codepoint(byte)
            return False
        decoder = state["decoder"]
        text = decoder.decode(bytes((byte,)), final=False)
        for char in text:
            self._append_decoded_codepoint(ord(char))
        return False

    def _finish_key(self, emit, end_offset: int) -> None:
        state = self._string
        if state is None or state["mode"] != "key":
            raise ValueError("canonical object key ended outside object state")
        frame = self._stack[-1]
        key = "".join(state["key_parts"])
        if frame.previous_key is not None and key <= frame.previous_key:
            raise ValueError("canonical object keys are duplicated or not strictly sorted")
        raw = bytes(state["key_raw"])
        start = state["start"]
        self._emit(emit, "key", frame.path + (key,), start, end_offset,
                   raw=raw, key=key)
        frame.previous_key = key
        frame.current_key = key
        frame.state = "colon"
        self._string = None

    def _start_number(self, byte: int, path, offset: int, emit) -> None:
        self._begin_scalar(emit, "number", path, offset, byte)
        if byte == ord("-"):
            state = "sign"
        elif byte == ord("0"):
            state = "zero"
        elif ord("1") <= byte <= ord("9"):
            state = "integer"
        else:
            raise ValueError("canonical JSON number must start with a digit or minus")
        self._number = {"state": state, "length": 1, "prefix": bytearray((byte,)),
                        "is_float": False, "negative_zero": byte == ord("-")}

    def _append_number_byte(self, byte: int) -> None:
        number = self._number
        if number["length"] < MAX_FLOAT_LEXEME_BYTES_V2:
            number["prefix"].append(byte)
        number["length"] += 1
        if number["is_float"] and number["length"] > MAX_FLOAT_LEXEME_BYTES_V2:
            raise C09CanonicalJSONUnsupportedV2("canonical floating-point lexeme exceeds the installed bound")

    def _mark_float(self, byte: int, state: str) -> None:
        number = self._number
        number["is_float"] = True
        if number["length"] + 1 > MAX_FLOAT_LEXEME_BYTES_V2:
            raise C09CanonicalJSONUnsupportedV2("canonical floating-point lexeme exceeds the installed bound")
        self._append_number_byte(byte)
        number["state"] = state

    def _number_step(self, byte: int) -> bool:
        """Consume a byte if it belongs to the number; otherwise finalize before it."""
        number = self._number
        state = number["state"]
        if state == "sign":
            if byte == ord("0"):
                number["negative_zero"] = True
                number["state"] = "negative_zero"
            elif ord("1") <= byte <= ord("9"):
                number["negative_zero"] = False
                number["state"] = "integer"
            else:
                raise ValueError("canonical JSON minus is not followed by a digit")
            self._append_number_byte(byte)
            return True
        if state in {"zero", "negative_zero"}:
            if byte == ord("."):
                self._mark_float(byte, "dot")
                return True
            if byte in (ord("e"), ord("E")):
                self._mark_float(byte, "exponent_mark")
                return True
            if ord("0") <= byte <= ord("9"):
                raise ValueError("canonical JSON integer has a leading zero")
            if byte in b",]}":
                return False
            raise ValueError("canonical JSON number is followed by invalid data")
        if state == "integer":
            if ord("0") <= byte <= ord("9"):
                self._append_number_byte(byte)
                return True
            if byte == ord("."):
                self._mark_float(byte, "dot")
                return True
            if byte in (ord("e"), ord("E")):
                self._mark_float(byte, "exponent_mark")
                return True
            if byte in b",]}":
                return False
            raise ValueError("canonical JSON number is followed by invalid data")
        if state == "dot":
            if not ord("0") <= byte <= ord("9"):
                raise ValueError("canonical JSON fraction requires a digit")
            number["state"] = "fraction"
            self._append_number_byte(byte)
            return True
        if state == "fraction":
            if ord("0") <= byte <= ord("9"):
                self._append_number_byte(byte)
                return True
            if byte in (ord("e"), ord("E")):
                self._mark_float(byte, "exponent_mark")
                return True
            if byte in b",]}":
                return False
            raise ValueError("canonical JSON number is followed by invalid data")
        if state == "exponent_mark":
            if byte in (ord("+"), ord("-")):
                number["state"] = "exponent_sign"
                self._append_number_byte(byte)
                return True
            if ord("0") <= byte <= ord("9"):
                number["state"] = "exponent"
                self._append_number_byte(byte)
                return True
            raise ValueError("canonical JSON exponent requires a digit")
        if state == "exponent_sign":
            if not ord("0") <= byte <= ord("9"):
                raise ValueError("canonical JSON exponent sign requires a digit")
            number["state"] = "exponent"
            self._append_number_byte(byte)
            return True
        if state == "exponent":
            if ord("0") <= byte <= ord("9"):
                self._append_number_byte(byte)
                return True
            if byte in b",]}":
                return False
            raise ValueError("canonical JSON number is followed by invalid data")
        raise ValueError("canonical JSON number parser entered an unknown state")

    def _validate_number(self) -> None:
        number = self._number
        if number["state"] in {"sign", "dot", "exponent_mark", "exponent_sign"}:
            raise ValueError("canonical JSON number ended in an incomplete grammar state")
        if not number["is_float"]:
            if number["negative_zero"]:
                raise ValueError("canonical JSON integer negative zero serializes as zero")
            return
        if number["length"] > MAX_FLOAT_LEXEME_BYTES_V2:
            raise C09CanonicalJSONUnsupportedV2("canonical floating-point lexeme exceeds the installed bound")
        try:
            lexeme = bytes(number["prefix"]).decode("ascii")
            parsed = float(lexeme)
        except (UnicodeDecodeError, ValueError, OverflowError) as exc:
            raise ValueError("canonical JSON floating-point number is invalid") from exc
        if not math.isfinite(parsed):
            raise ValueError("canonical JSON number must be finite")
        encoded = json.dumps(parsed, ensure_ascii=self.ensure_ascii,
                             separators=(",", ":"), allow_nan=False).encode("ascii")
        if encoded != bytes(number["prefix"]):
            raise ValueError("canonical JSON floating-point spelling is not canonical")

    def _finish_number(self, end_offset: int, end_index: int | None,
                       fragment: bytes | None, base: int, emit,
                       chunk_start: int | None) -> None:
        self._validate_number()
        if fragment is not None and end_index is not None:
            self._chunk(fragment, chunk_start, end_index, base, emit)
        self._number = None
        active = self._active_scalar
        if active is None:
            raise ValueError("canonical number lost its scalar event")
        self._end_scalar(emit, end_offset)

    def _start_value(self, byte: int, offset: int, emit) -> None:
        path = self._value_path()
        if byte == ord("{"):
            if len(self._stack) >= self.max_depth:
                raise C09CanonicalJSONUnsupportedV2("canonical JSON nesting exceeds the installed depth bound")
            self._emit(emit, "object_start", path, offset, offset + 1, raw=b"{")
            self._stack.append(_ContainerV2("object", path, "key_or_end"))
            return
        if byte == ord("["):
            if len(self._stack) >= self.max_depth:
                raise C09CanonicalJSONUnsupportedV2("canonical JSON nesting exceeds the installed depth bound")
            self._emit(emit, "array_start", path, offset, offset + 1, raw=b"[")
            self._stack.append(_ContainerV2("array", path, "value_or_end"))
            return
        if byte == ord('"'):
            self._begin_scalar(emit, "string", path, offset, byte)
            self._begin_string(mode="value", path=path, start=offset)
            return
        if byte == ord("-") or ord("0") <= byte <= ord("9"):
            self._start_number(byte, path, offset, emit)
            return
        if byte in (ord("t"), ord("f"), ord("n")):
            expected = b"true" if byte == ord("t") else b"false" if byte == ord("f") else b"null"
            kind = expected.decode("ascii")
            self._begin_scalar(emit, kind, path, offset, byte)
            self._literal = {"expected": expected, "position": 1, "start": offset,
                             "path": path, "kind": kind}
            return
        raise ValueError("canonical JSON root/object/array value has an invalid first byte")

    def _close_container(self, byte: int, offset: int, emit) -> None:
        if not self._stack:
            raise ValueError("canonical JSON has an unmatched container terminator")
        frame = self._stack[-1]
        if byte == ord("}"):
            if frame.kind != "object" or frame.state not in {"key_or_end", "comma_or_end"}:
                raise ValueError("canonical JSON object is not closed at a value boundary")
            event = "object_end"
        else:
            if frame.kind != "array" or frame.state not in {"value_or_end", "comma_or_end"}:
                raise ValueError("canonical JSON array is not closed at a value boundary")
            event = "array_end"
        self._emit(emit, event, frame.path, offset, offset + 1,
                   raw=bytes((byte,)))
        self._stack.pop()
        self._complete_value()

    def _normal_byte(self, byte: int, offset: int, emit) -> None:
        if byte in b" \t\r\n":
            raise ValueError("canonical JSON contains forbidden whitespace")
        if not self._stack:
            if self._root_done:
                raise ValueError("canonical JSON contains trailing data")
            self._start_value(byte, offset, emit)
            return
        frame = self._stack[-1]
        if frame.kind == "object":
            if frame.state in {"key_or_end", "key_required"}:
                if byte == ord("}") and frame.state == "key_or_end":
                    self._close_container(byte, offset, emit)
                    return
                if byte != ord('"'):
                    raise ValueError("canonical JSON object requires a quoted key")
                self._begin_string(mode="key", path=frame.path, start=offset)
                self._string["key_raw"].append(byte)
                return
            if frame.state == "colon":
                if byte != ord(":"):
                    raise ValueError("canonical JSON object key requires a colon")
                frame.state = "value"
                return
            if frame.state == "value":
                self._start_value(byte, offset, emit)
                return
            if frame.state == "comma_or_end":
                if byte == ord(","):
                    frame.state = "key_required"
                    return
                if byte == ord("}"):
                    self._close_container(byte, offset, emit)
                    return
                raise ValueError("canonical JSON object requires comma or closing brace")
            raise ValueError("canonical JSON object entered an unknown state")
        if frame.state in {"value_or_end", "value_required"}:
            if byte == ord("]") and frame.state == "value_or_end":
                self._close_container(byte, offset, emit)
                return
            self._start_value(byte, offset, emit)
            return
        if frame.state == "comma_or_end":
            if byte == ord(","):
                frame.state = "value_required"
                return
            if byte == ord("]"):
                self._close_container(byte, offset, emit)
                return
            raise ValueError("canonical JSON array requires comma or closing bracket")
        raise ValueError("canonical JSON array entered an unknown state")

    def feed(self, fragment: bytes, emit: Callable[[C09JSONEventV2], None]) -> C09JSONStreamProgressV2:
        if self._finished or self._failed:
            raise ValueError("canonical JSON stream is no longer feedable")
        if type(fragment) is not bytes:
            raise TypeError("canonical JSON fragments must be exact bytes")
        if len(fragment) > MAX_FRAGMENT_BYTES_V2:
            raise C09CanonicalJSONUnsupportedV2("canonical JSON fragment exceeds 16KiB")
        if not callable(emit):
            raise TypeError("canonical JSON event consumer must be callable")
        base = self._byte_count
        self._emit_callback = emit
        self._feeding = True
        self._sha256.update(fragment)
        i = 0
        chunk_start: int | None = 0 if self._active_scalar is not None else None
        try:
            while i < len(fragment):
                offset = base + i
                if self._string is not None:
                    state = self._string
                    byte = fragment[i]
                    if state["mode"] == "key":
                        state["key_raw"].append(byte)
                        if len(state["key_raw"]) > self.max_key_bytes * 6 + 2:
                            raise C09CanonicalJSONUnsupportedV2("canonical object key wire spelling exceeds its bounded buffer")
                    closed = self._consume_string_byte(byte, offset)
                    i += 1
                    if closed:
                        if state["mode"] == "key":
                            self._finish_key(emit, base + i)
                        else:
                            self._chunk(fragment, chunk_start, i, base, emit)
                            active = self._active_scalar
                            self._end_scalar(emit, base + i)
                        chunk_start = None
                    continue

                if self._literal is not None:
                    literal = self._literal
                    byte = fragment[i]
                    expected = literal["expected"]
                    position = literal["position"]
                    if byte != expected[position]:
                        raise ValueError("canonical JSON literal spelling differs")
                    literal["position"] = position + 1
                    i += 1
                    if literal["position"] == len(expected):
                        self._chunk(fragment, chunk_start, i, base, emit)
                        self._literal = None
                        self._end_scalar(emit, base + i)
                        chunk_start = None
                    continue

                if self._number is not None:
                    if self._number_step(fragment[i]):
                        i += 1
                        continue
                    self._finish_number(base + i, i, fragment, base, emit, chunk_start)
                    chunk_start = None
                    continue

                prior_scalar = self._active_scalar
                self._normal_byte(fragment[i], offset, emit)
                if self._active_scalar is not None and prior_scalar is None:
                    chunk_start = i
                i += 1

            if self._active_scalar is not None:
                self._chunk(fragment, chunk_start, len(fragment), base, emit)
            self._byte_count = base + len(fragment)
            return C09JSONStreamProgressV2(len(fragment), self._byte_count, not self._root_done)
        except Exception:
            self._failed = True
            raise
        finally:
            self._feeding = False

    def finish(self) -> C09JSONStreamResultV2:
        if self._finished or self._failed:
            raise ValueError("canonical JSON stream cannot be finished in its current state")
        try:
            if self._string is not None or self._literal is not None:
                raise ValueError("canonical JSON ended inside a string, escape, or literal")
            if self._number is not None:
                self._finish_number(self._byte_count, None, None, self._byte_count, self._emit_callback, None)
            if not self._root_done or self._stack:
                raise ValueError("canonical JSON document is incomplete")
            self._finished = True
            return C09JSONStreamResultV2(self._byte_count, self._sha256.hexdigest())
        except Exception:
            self._failed = True
            raise
