"""Pure exact Joint Source-purpose recipe; carries no read or execution authority."""
JOINT_SOURCE_METADATA_FIELDS_V3=frozenset(("schema","namespace","plan_id","window_id","revision",
    "long_term_plan_ref","long_term_plan_revision","current_window_ref","state","source_refs","purpose",
    "audience","node_drafts","original_deadline_utc"))

def artifact_joint_metadata_path_v3(path):
    return not path or path[0]in JOINT_SOURCE_METADATA_FIELDS_V3

def artifact_joint_source_groups_from_metadata_v3(*,namespace,matched_rows,metadata):
    """metadata maps actual signed-R tokens to (actual revision, fixed projection)."""
    if len(matched_rows)>1:raise ValueError("Artifact current Joint task matches conflicting actual HMAC rows")
    if not matched_rows:return ()
    row=matched_rows[0]
    if row["retired"]:raise ValueError("Artifact actual Joint task is opaquely retired")
    window_revision,window=metadata[row["window_ref"]]
    plan_revision,plan=metadata[row["plan_ref"]]
    ns={"bot_id":namespace.bot_id,"persona_id":namespace.persona_id}
    if(window["schema"]!="d08.joint-window.v1"or plan["schema"]!="d08.long-term-plan.v1"
            or window["namespace"]!=ns or plan["namespace"]!=ns
            or window["long_term_plan_ref"]!=row["plan_ref"]
            or window_revision<row["window_birth_revision"]):
        raise ValueError("Artifact Joint purpose recipe differs from actual matched Window/LongPlan lineage")
    nodes=tuple(node for node in window["node_drafts"]if node["node_id"]==row["node_id"])
    if len(nodes)!=1:raise ValueError("Artifact actual matched Joint node is missing or ambiguous")
    node=nodes[0]
    from ..memory_types import _PURPOSES
    if plan["purpose"]not in _PURPOSES or node["purpose"]not in {"context","expression","consolidation"}:
        raise ValueError("Artifact actual Joint Source purpose is outside its existing domain")
    return (("joint_longterm_plan",tuple(plan["source_refs"]),(plan["purpose"],),tuple(plan["audience"])),
        ("joint_window_node",tuple(node["source_refs"]),(node["purpose"],),tuple(node["audience"])))
