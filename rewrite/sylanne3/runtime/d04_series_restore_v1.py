"""Current Authority authentication of an immutable same-machine series packet."""
from dataclasses import dataclass
import hashlib
from .d04_appraisal_driver_v3 import read_d04_original_v3
from ..authority_service.d04_series_contract_v1 import to_wire
from ..runtime_contracts import canonical_serialize


def read_installed_d04_series_packet_v1(graph, binding):
    store = graph._GraphCoordinator__store
    port = graph._GraphCoordinator__c04_authority_port_v3
    with store._lock:
        raw = read_d04_original_v3(store._db, binding.numeric.namespace,
                                  "series_chunk_math", binding.numeric.operation_id)
    if raw is None:
        return port.series(binding, "restore")
    _, terminal = port.series(binding, "inspect")
    if terminal is None:
        raise ValueError("series restore has no actual independent terminal")
    packet = canonical_serialize({"terminal": to_wire(terminal), "math": raw[0]}).encode("utf-8")
    # The local bytes are never submitted as Authority evidence. Each restore
    # still obtains a newly qualified full-packet manifest from the service.
    return port.series(binding, "restore", local_packet=packet)


@dataclass(frozen=True, slots=True)
class _SeriesPrefixStructuresV1:
    """Private structures awaiting the mandatory complete final verifier."""
    chunks: tuple
    bindings: tuple
    terminals: tuple


def _collect_installed_d04_series_prefix_for_final_verifier_v1(graph, root):
    from .d04_installed_stage_fence_v3 import _D04PhaseTimingsV1
    timings = _D04PhaseTimingsV1(root.root_ref, deadline_utc=root.prepared.binding.deadline_utc)
    with timings.measure("prefix_collection"):
        return _collect_d04_series_prefix_structures_v1(graph, root, timings)


def _collect_d04_series_prefix_structures_v1(graph, root, timings):
    from .d04_series_execution_v1 import chunk_operation_v1
    from .d04_series_store_v1 import read_d04_series_chunk_prepared_v1
    from .d04_series_codec_v1 import _decode_series_chunk_for_final_verifier_v1
    from .d04_series_prefix_manifest_v1 import D04SeriesPrefixManifestV1
    from ..runtime_contracts import canonical_digest
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__c04_authority_port_v3
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            bindings = []
            start = 0
            while start < root.frozen.plan.total_step_count:
                prepared = read_d04_series_chunk_prepared_v1(db, root.prepared.binding.namespace,
                    chunk_operation_v1(root, start))
                end = start + len(root.frozen.plan.chunk(start))
                if (prepared is None or (prepared[0].root_ref, prepared[0].root_digest,
                        prepared[0].plan_digest, prepared[0].start_step_index, prepared[0].end_step_index) !=
                        (root.root_ref, root.digest, root.frozen.plan.digest, start, end)):
                    raise ValueError("series final collector lacks exact complete planned preparation")
                bindings.append(prepared[0])
                start = end
            with timings.measure("prefix_manifest_rpc"):
                manifest = port.series(bindings[-1], "prefix_manifest")
            if (type(manifest) is not D04SeriesPrefixManifestV1
                    or (manifest.root_ref, manifest.root_digest, manifest.plan_digest,
                        manifest.total_step_count, manifest.chunk_step_limit, manifest.chunk_count) != (root.root_ref, root.digest,
                        root.frozen.plan.digest, root.frozen.plan.total_step_count, root.frozen.plan.chunk_step_limit, len(bindings))):
                raise ValueError("series final collector actual Authority manifest/root/plan differs")
            chunks, terminals = [], []
            for binding, entry in zip(bindings, manifest.packets):
                terminal = entry.terminal
                raw = read_d04_original_v3(db, binding.numeric.namespace, "series_chunk_math", binding.numeric.operation_id)
                if raw is None or terminal.binding != binding:
                    raise ValueError("series final collector actual terminal/packet absent")
                with timings.measure("packet_hash", chunk_start=binding.start_step_index):
                    packet = canonical_serialize({"terminal": to_wire(terminal), "math": raw[0]}).encode("utf-8")
                    if len(packet) != entry.length or hashlib.sha256(packet).hexdigest() != entry.sha256:
                        raise ValueError("series local packet differs from this actual Authority prefix manifest")
                with timings.measure("packet_decode", chunk_start=binding.start_step_index):
                    chunk = _decode_series_chunk_for_final_verifier_v1(raw[0])
                native = chunk.full.production_binding
                if ((chunk.root_digest, chunk.plan_digest, chunk.start_step_index,
                        chunk.end_step_index, chunk.predecessor_digest) != (binding.root_digest, binding.plan_digest,
                        binding.start_step_index, binding.end_step_index, binding.predecessor_digest)
                        or terminal.measurement.chunk_math_digest != chunk.digest
                        or terminal.measurement.endpoint_digest != canonical_digest(chunk.endpoints)
                        or native.manifest_sha256 != binding.numeric.native_manifest_sha256
                        or native.native_sha256 != binding.numeric.native_sha256 or native.abi_version != 2):
                    raise ValueError("series manifest packet structural/native commitments differ")
                chunks.append(chunk)
                terminals.append(terminal)
            return _SeriesPrefixStructuresV1(tuple(chunks), tuple(bindings), tuple(terminals))
        finally:
            db.rollback()
