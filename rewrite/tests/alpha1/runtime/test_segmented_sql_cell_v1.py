"""Permanent actual-SQL legacy-cell and parser-copy boundaries.

These software tests grant no installed capture/Source/selection authority and
make no RSS/OS I/O/resource qualification claim. No original fixture is reused.
"""
from hashlib import sha256
import json
import sqlite3
import pytest
from sylanne3.runtime.c09_paged_sql_v2 import (C09BatchBudgetV2,C09SqlByteMeterV2,
    legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2,C09PagedCaptureHold)
from sylanne3.runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2


def test_actual_sqlite_large_text_incremental_bytes_and_rowid_refusals():
    value=json.dumps({'text':'中'*65536},ensure_ascii=True,sort_keys=True,separators=(',',':')).encode('utf-8')
    assert len(value)>262144
    db=sqlite3.connect(':memory:')
    db.execute('CREATE TABLE old_source (identity TEXT PRIMARY KEY,value TEXT NOT NULL)')
    db.execute('INSERT INTO old_source VALUES(?,?)',('actual-source',value.decode('utf-8')));db.commit()
    digest=sha256();offset=0;quanta=0
    try:
        while offset<len(value):
            meter=C09SqlByteMeterV2(C09BatchBudgetV2(100,262144,25000000,250000000,8388608))
            with legacy_cell_read_transaction_v2(db):
                count=min(16384,len(value)-offset)
                block,total,kind=read_legacy_sql_cell_fragment_v2(db,table='old_source',column='value',
                    where='identity=?',parameters=('actual-source',),start=offset,length=count,meter=meter)
                assert total==len(value) and kind=='text' and block==value[offset:offset+count]
                digest.update(block);offset+=len(block)
            assert not db.in_transaction and meter.consumed_bytes<=262144
            quanta+=1
        assert quanta>1 and digest.hexdigest()==sha256(value).hexdigest()
        db.execute('CREATE TABLE unsupported (identity TEXT PRIMARY KEY,value TEXT) WITHOUT ROWID')
        db.execute('INSERT INTO unsupported VALUES(?,?)',('source','{}'));db.commit()
        with legacy_cell_read_transaction_v2(db),pytest.raises(C09PagedCaptureHold,match='rowid'):
            read_legacy_sql_cell_fragment_v2(db,table='unsupported',column='value',where='identity=?',
                parameters=('source',),start=0,length=2,meter=C09SqlByteMeterV2(C09BatchBudgetV2(100,262144,25000000,250000000,8388608)))
        db.execute('CREATE TABLE shadowed (rowid TEXT,_rowid_ TEXT,oid TEXT,value TEXT)')
        db.execute('INSERT INTO shadowed VALUES(?,?,?,?)',('a','b','c','{}'));db.commit()
        with legacy_cell_read_transaction_v2(db),pytest.raises(C09PagedCaptureHold,match='unshadowed'):
            read_legacy_sql_cell_fragment_v2(db,table='shadowed',column='value',where='rowid=?',
                parameters=('a',),start=0,length=2,meter=C09SqlByteMeterV2(C09BatchBudgetV2(100,262144,25000000,250000000,8388608)))
    finally:db.close()


def test_canonical_parser_quantum_copy_keeps_real_hash_and_utf8_prefix():
    encoded=json.dumps({'text':'中😀\n'+('x'*20000)},ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')
    split=encoded.index('中'.encode('utf-8'))+1
    parser=C09CanonicalJSONStreamV2(ensure_ascii=False)
    parser.feed(encoded[:split],lambda event:None)
    prior=parser.byte_count
    clone=parser.copy()
    for start in range(split,len(encoded),16384):clone.feed(encoded[start:start+16384],lambda event:None)
    assert clone.finish().sha256==sha256(encoded).hexdigest()
    assert parser.byte_count==prior
    for start in range(split,len(encoded),16384):parser.feed(encoded[start:start+16384],lambda event:None)
    assert parser.finish().sha256==sha256(encoded).hexdigest()

    for invalid in (b'{"b":1,"a":2}',b'{"a":1,"a":2}',b'{"text":"\xff"}'):
        refused=C09CanonicalJSONStreamV2(ensure_ascii=False)
        with pytest.raises((ValueError,UnicodeDecodeError)):
            refused.feed(invalid,lambda event:None)
            refused.finish()



def test_actual_legacy_schema_uses_reserved_meter_without_changing_commitment():
    from sylanne3.runtime.c09_paged_sql_v2 import read_c09_table_shape_v2,c09_sql_meter_quantum_v2
    db=sqlite3.connect(':memory:')
    db.execute('CREATE TABLE old_source (identity TEXT PRIMARY KEY,value TEXT NOT NULL)')
    budget=C09BatchBudgetV2(100,262144,25000000,250000000,8388608)
    try:
        original=read_c09_table_shape_v2(db,'old_source')
        meter=C09SqlByteMeterV2(budget)
        with legacy_cell_read_transaction_v2(db),c09_sql_meter_quantum_v2(meter):
            actual=read_c09_table_shape_v2(db,'old_source',meter=meter)
        assert actual==original and actual.primary_key_columns==('identity',)
        assert 0<meter.read_bytes<meter.consumed_bytes<budget.max_bytes
        assert meter.encoded_bytes>0 and meter.written_bytes==0
        exhausted=C09SqlByteMeterV2(budget);exhausted.charge_read(budget.max_bytes-64)
        with legacy_cell_read_transaction_v2(db),c09_sql_meter_quantum_v2(exhausted):
            with pytest.raises(C09PagedCaptureHold,match='continuation before this I/O'):
                read_c09_table_shape_v2(db,'old_source',meter=exhausted)
        assert exhausted.consumed_bytes==budget.max_bytes-64 and not db.in_transaction
    finally:db.close()



def test_actual_canonical_outputs_count_once_across_nested_c09_quantum():
    from sylanne3.runtime_contracts import (
        canonical_serialize,canonical_digest,meter_canonical_outputs,current_canonical_output_meter)
    from sylanne3.runtime.c09_paged_sql_v2 import c09_sql_meter_quantum_v2,canonical_serialize as sql_serialize
    from sylanne3.runtime.c09_paged_capture_contract_v2 import meter_c09_commitments_v2,_commit_serialize
    value={'source':'中😀','namespace':['bot','persona']}
    from sylanne3.authority_service.c09_storage_control_v1 import canonical as control_canonical
    control_original=control_canonical(value);control_size=len(control_original.encode('utf-8'))
    original=canonical_serialize(value);size=len(original.encode('utf-8'))
    assert control_original!=original
    meter=C09SqlByteMeterV2(C09BatchBudgetV2(100,262144,25000000,250000000,8388608))
    assert current_canonical_output_meter() is None
    with c09_sql_meter_quantum_v2(meter):
        assert canonical_serialize(value)==original
        assert meter.encoded_bytes==size
        with meter_c09_commitments_v2(meter),meter_canonical_outputs(meter):
            assert _commit_serialize(value)==original
            assert sql_serialize(value)==original
            assert canonical_digest(value)==sha256(original.encode('utf-8')).hexdigest()
        assert meter.encoded_bytes==4*size
        assert meter.encode(value,reserved_max_bytes=size)==original
        assert meter.encoded_bytes==5*size
        exhausted=C09SqlByteMeterV2(meter.budget);exhausted.charge_read(meter.budget.max_bytes-size+1)
        with meter_canonical_outputs(exhausted),pytest.raises(C09PagedCaptureHold,match='continuation before this I/O'):
            canonical_serialize(value)
        assert current_canonical_output_meter() is meter
        assert control_canonical(value)==control_original
        assert meter.encoded_bytes==5*size+control_size
    assert current_canonical_output_meter() is None
    assert canonical_serialize(value)==original and meter.encoded_bytes==5*size+control_size
    assert meter.read_bytes==meter.written_bytes==0



def test_memory_source_stream_actual_rules_large_text_and_cold_prefix_copy():
    from sylanne3.runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
    from sylanne3.runtime.c09_paged_sql_v2 import c09_sql_meter_quantum_v2
    from sylanne3.memory_types import SourceRecord
    from sylanne3.runtime_contracts import canonical_serialize
    original = SourceRecord('source', '中' * 65536, 'speaker', 'reported',
        'unknown', None, 1.0, 'root', ('owner',), ('audit',)).to_dict()
    def consume(value):
        encoded = canonical_serialize(value).encode()
        parser = C09MemorySourceJSONStreamV3(ensure_ascii=True)
        for offset in range(0, len(encoded), 16384):
            meter = C09SqlByteMeterV2(C09BatchBudgetV2(100,262144,25000000,250000000,8388608))
            with c09_sql_meter_quantum_v2(meter):
                updated = parser.copy()
                updated.feed(encoded[offset:offset+16384], lambda event: None)
                assert parser.byte_count == offset
                parser = updated
        with c09_sql_meter_quantum_v2(C09SqlByteMeterV2(C09BatchBudgetV2(100,262144,25000000,250000000,8388608))):
            result = parser.finish()
        assert result.sha256 == sha256(encoded).hexdigest()
        assert 'text' not in parser._source_metadata
        return parser
    assert consume(original)._source_text_characters == 65536
    assert consume({**original, 'text': '😀' * 65536})._source_text_characters == 65536
    assert consume({**original, 'text': '\t\u3000'})._source_text_characters == 2
    for patch in ({'text':'中'*65537}, {'text':''}, {'audiences':['*']},
            {'purposes':['invalid']}, {'parent_source_ids':['same','same']},
            {'source_kind':'invented'}, {'recorded_at':-1}, {'occurred_at':True},
            {'speaker_id':''}, {'extra_field':1}):
        value = {**original, **patch}
        with pytest.raises((ValueError, TypeError)):
            SourceRecord.from_dict(value)
        with pytest.raises((ValueError, TypeError)):
            consume(value)



def test_memory_source_stream_two_pass_metadata_arena_and_duplicate_refusal():
    from sylanne3.runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
    from sylanne3.runtime.c09_paged_sql_v2 import c09_sql_meter_quantum_v2
    from sylanne3.memory_types import SourceRecord
    from sylanne3.runtime_contracts import canonical_serialize
    source = SourceRecord('source', 'actual text', 'speaker', 'reported',
        'unknown', None, 1.0, 'root', ('owner',), ('audit',)).to_dict()
    source['parent_source_ids'] = [f'{index:06d}' for index in range(100000)]
    encoded = canonical_serialize(source).encode()
    parser = C09MemorySourceJSONStreamV3(ensure_ascii=True)
    independent = C09MemorySourceJSONStreamV3(ensure_ascii=True, source_arena=parser._source_arena)
    with pytest.raises(C09PagedCaptureHold, match='reserved arena'):
        for offset in range(0,len(encoded),16384):
            meter = C09SqlByteMeterV2(C09BatchBudgetV2(100,262144,25000000,250000000,8388608))
            with c09_sql_meter_quantum_v2(meter):
                parser.feed(encoded[offset:offset+16384],lambda event:None)
                independent.feed(encoded[offset:offset+16384],lambda event:None)
    duplicate = {**source,'parent_source_ids':['same','same']}
    parser = C09MemorySourceJSONStreamV3(ensure_ascii=True)
    with c09_sql_meter_quantum_v2(C09SqlByteMeterV2(C09BatchBudgetV2(100,262144,25000000,250000000,8388608))):
        with pytest.raises(ValueError,match='unique strings'):
            parser.feed(canonical_serialize(duplicate).encode(),lambda event:None)
