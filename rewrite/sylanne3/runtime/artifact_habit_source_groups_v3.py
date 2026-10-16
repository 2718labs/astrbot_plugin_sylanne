"""Pure fixed Habit Artifact context Source recipe; grants no permissions."""
def artifact_habit_interpretation_metadata_path_v3(path):
    return not path or path[0]=="source_refs"

def artifact_habit_context_source_recipe_v3(*,definition,cue_original_ref,interpretation_metadata):
    from ..domains.d10.habit_policy_v1 import HabitPolicyDefinitionV1
    if type(definition)is not HabitPolicyDefinitionV1 or definition.executor_kind!="draft_file":
        raise TypeError("actual typed Artifact Habit definition metadata required")
    needed=[]
    if definition.cue_predicate.observation_provider=="d07.habit-cue.v1":needed.append(cue_original_ref)
    if definition.stop_predicate.observation_provider=="d07.habit-stop.v1":
        needed.append(dict(definition.stop_predicate.parameters)["interpretation_ref"])
    roots=set(definition.source_refs)
    for ref in needed:roots.update(interpretation_metadata[ref]["source_refs"])
    return("habit_context",tuple(sorted(roots)),("context",),definition.audience)
