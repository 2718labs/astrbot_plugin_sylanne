"""Public identity of one administrator-installed final handoff pairing."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from .contract import identifier


SCHEMA = "authority-final-handoff-pairing-v1"


@dataclass(frozen=True, slots=True)
class FinalHandoffPairingV1:
    authority_id: str
    namespace: str
    installation_id: str
    issuer_id: str
    reverse_profile_id: str
    reverse_host: str
    reverse_port: int
    reverse_server_name: str
    reverse_expected_host_certificate_sha256: str
    reverse_client_certificate_sha256: str
    installation_manifest_digest: str
    configuration_digest: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("final handoff pairing schema differs")
        for name in ("authority_id", "namespace", "installation_id", "issuer_id",
                     "reverse_profile_id", "reverse_host", "reverse_server_name"):
            identifier(getattr(self, name), name)
        if type(self.reverse_port) is not int or not 1 <= self.reverse_port <= 65535:
            raise ValueError("invalid reverse port")
        for name in ("reverse_expected_host_certificate_sha256",
                     "reverse_client_certificate_sha256",
                     "installation_manifest_digest", "configuration_digest"):
            value = getattr(self, name)
            if (type(value) is not str or len(value) != 64
                    or any(ch not in "0123456789abcdef" for ch in value)):
                raise ValueError(f"invalid {name}")
        if self.configuration_digest != self.digest_public_fields(self.public_fields()):
            raise ValueError("final handoff pairing digest differs")

    def public_fields(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__
                if name not in {"configuration_digest", "schema"}}

    @staticmethod
    def digest_public_fields(fields: dict[str, object]) -> str:
        encoded = json.dumps(fields, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_wire(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_wire(cls, value: object) -> "FinalHandoffPairingV1":
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("final handoff pairing wire fields differ")
        result = cls(**value)
        if result.to_wire() != value:
            raise ValueError("final handoff pairing wire is not canonical")
        return result


__all__ = ["SCHEMA", "FinalHandoffPairingV1"]
