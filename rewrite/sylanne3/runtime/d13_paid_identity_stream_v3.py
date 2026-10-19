"""Pure bounded D13 identity and encoded-string parsers used by runtime and capture."""
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2


class _D13PaidIdentityStreamV3(C09CanonicalJSONStreamV2):
    """Exact plain outer identity wire and real top-level byte ranges."""
    def __init__(self,kind='intent',**profile):
        from dataclasses import fields
        from ..runtime.d13_paid_intent_original_v1 import D13PaidIntentOriginalV1,D13PaidCallOriginalV1
        super().__init__(**profile);self.kind=kind;self.fields=set();self.starts={};self.ranges={};self.typed_offsets={}
        cls=D13PaidIntentOriginalV1 if kind=='intent' else D13PaidCallOriginalV1
        self.expected={field.name for field in fields(cls)}

    def copy(self):
        result=super().copy();result.kind=self.kind;result.fields=set(self.fields);result.expected=set(self.expected)
        result.starts=dict(self.starts);result.ranges=dict(self.ranges);result.typed_offsets=dict(self.typed_offsets);return result

    def _emit(self,emit,kind,path,start,end,**values):
        from ..runtime_contracts import NamespaceId
        from ..domains.d13.paid_lifecycle import D13PaidOriginalBindingV1
        from ..model_broker.d13_precompression import D13ExactTokenCountV1
        from dataclasses import fields
        typed={'namespace':NamespaceId}
        if self.kind=='intent':typed.update(binding=D13PaidOriginalBindingV1,exact_count=D13ExactTokenCountV1)
        if kind=='key' and len(path)==1:
            if values['key'] not in self.expected:raise ValueError('paid identity original has another exact root schema')
            self.fields.add(values['key'])
        if kind=='key' and len(path)==2 and path[0] in typed:
            if values['key'] not in {field.name for field in fields(typed[path[0]])}:
                raise ValueError('paid identity typed member has another exact plain schema')
        if kind in {'object_start','array_start','scalar_start'}:
            if not path and kind!='object_start':raise ValueError('paid identity original must be plain object')
            if len(path)==1:
                field=path[0];self.starts[path]=start
                if field in typed:
                    if kind=='object_start':self.typed_offsets[path]=(start+1,typed[field])
                    elif not (field=='exact_count' and kind=='scalar_start' and values.get('scalar_kind')=='null'):
                        raise ValueError('paid identity typed member type differs')
                elif field in {'frozen_json','request_json'}:
                    if kind!='scalar_start' or values.get('scalar_kind')!='string':raise ValueError('paid identity inner wire must remain original encoded string')
                elif kind=='array_start':raise ValueError('paid identity field cannot be an array')
        if kind in {'object_end','array_end','scalar_end'} and path in self.starts:
            self.ranges[path]=(self.starts.pop(path),end)
        super()._emit(emit,kind,path,start,end,**values)

    def finish(self):
        result=super().finish()
        if self.fields!=self.expected:raise ValueError('paid identity original complete root schema differs')
        return result


class _D13PaidEncodedStringStreamV3(C09CanonicalJSONStreamV2):
    """Decode exactly one actual canonical ASCII string, with bounded output."""
    def __init__(self,**profile):
        super().__init__(**profile);self.pending=bytearray();self.decoded_bytes=0

    def copy(self):
        result=super().copy();result.pending=bytearray(self.pending);result.decoded_bytes=self.decoded_bytes;return result

    def _emit(self,emit,kind,path,start,end,**values):
        if kind=='scalar_start' and (path or values.get('scalar_kind')!='string'):
            raise ValueError('paid encoded inner wire must be exactly one string')
        if kind in {'object_start','array_start'}:raise ValueError('paid encoded inner wire cannot be an object or array')
        super()._emit(emit,kind,path,start,end,**values)

    def _append_decoded_codepoint(self,codepoint):
        state=self._string
        if state is not None and state['mode']=='value':
            if state['path'] or codepoint>=128:raise ValueError('paid decoded inner wire differs from actual canonical ASCII profile')
            if len(self.pending)>=8192:raise ValueError('paid decoded inner fragment exceeds actual source fragment bound')
            self.pending.append(codepoint);self.decoded_bytes+=1
        return super()._append_decoded_codepoint(codepoint)
