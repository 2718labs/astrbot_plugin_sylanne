"""Distinct v6 generation/review seals over unchanged identity field semantics."""
from dataclasses import dataclass,fields
from ..model_broker.natural_reply_history_v6 import TEMPLATE_VERSION
from ..runtime_contracts import NATURAL_REPLY_REVIEW_WORKFLOW_V2
from .natural_original_v3 import (NaturalReplyGenerationOriginalSealV3,NaturalReplyReviewOriginalSealV3,
    TEMPLATE_VERSION as LEGACY_GENERATION_TEMPLATE,NATURAL_REPLY_REVIEW_WORKFLOW_V1)

GENERATION_SEAL_SCHEMA_V6='sylanne.d09.natural_generation_seal.v6'
REVIEW_SEAL_SCHEMA_V6='sylanne.d09.natural_review_seal.v6'

@dataclass(frozen=True,slots=True)
class NaturalReplyGenerationOriginalSealV6(NaturalReplyGenerationOriginalSealV3):
    template_version: str=TEMPLATE_VERSION
    schema: str=GENERATION_SEAL_SCHEMA_V6
    def __post_init__(self):
        if (self.schema,self.template_version)!=(GENERATION_SEAL_SCHEMA_V6,TEMPLATE_VERSION):
            raise ValueError('v6 generation keeps its actual named template and original schema')
        values={field.name:getattr(self,field.name) for field in fields(self)}
        values.update(schema='sylanne.d09.natural_generation_seal.v3',template_version=LEGACY_GENERATION_TEMPLATE)
        NaturalReplyGenerationOriginalSealV3(**values)

@dataclass(frozen=True,slots=True)
class NaturalReplyReviewOriginalSealV6(NaturalReplyReviewOriginalSealV3):
    template_version: str=NATURAL_REPLY_REVIEW_WORKFLOW_V2
    schema: str=REVIEW_SEAL_SCHEMA_V6
    def __post_init__(self):
        if (self.schema,self.template_version)!=(REVIEW_SEAL_SCHEMA_V6,NATURAL_REPLY_REVIEW_WORKFLOW_V2):
            raise ValueError('v6 review keeps its independent actual semantic review template and schema')
        values={field.name:getattr(self,field.name) for field in fields(self)}
        values.update(schema='sylanne.d09.natural_review_seal.v3',template_version=NATURAL_REPLY_REVIEW_WORKFLOW_V1)
        NaturalReplyReviewOriginalSealV3(**values)
