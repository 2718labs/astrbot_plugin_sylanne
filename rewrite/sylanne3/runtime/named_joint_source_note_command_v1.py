"""Typed original SourceNote command carried by a named additional restriction."""
from dataclasses import dataclass
from ..authority_service.current_foreground_activity_v1 import ForegroundActivityRequestV1
from ..authority_service.current_owner_source_note_task_v1 import OwnerTaskActivityRequestV1
from .d08_personal_candidate_v1 import ConsumePersonalDecisionRequestV1

@dataclass(frozen=True,slots=True)
class ManagedSourceNotePreparationRequestV1:
    original_selector:ForegroundActivityRequestV1|OwnerTaskActivityRequestV1
    command:ConsumePersonalDecisionRequestV1
    def __post_init__(self):
        if type(self.original_selector)not in {ForegroundActivityRequestV1,OwnerTaskActivityRequestV1}or type(self.command)is not ConsumePersonalDecisionRequestV1:
            raise TypeError('Named SourceNote requires its exact existing original selector and closed Consume command')
