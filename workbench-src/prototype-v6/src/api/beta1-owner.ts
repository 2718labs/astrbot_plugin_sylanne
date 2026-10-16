import { hasFields, isInteger, isRecord, isText } from './contract.ts'
export interface EditorSpec {kind:'text'|'number'|'integer'|'boolean'|'object'|'array'|'tuple';nullable?:boolean;constant?:string;choices?:readonly string[];fields?:Record<string,EditorSpec>;item?:EditorSpec;items?:EditorSpec[]}
export const BETA1_OPERATIONS={
  "register_calibration_policy_v1": {
    "label": "登记能力校准政策",
    "domain": "self",
    "purpose": "consolidation",
    "request": {
      "kind": "object",
      "fields": {
        "value": {
          "kind": "object",
          "fields": {
            "runtime_identity": {
              "kind": "object",
              "fields": {
                "namespace": {
                  "kind": "object",
                  "fields": {
                    "bot_id": {
                      "kind": "text"
                    },
                    "persona_id": {
                      "kind": "text"
                    }
                  }
                },
                "authority_id": {
                  "kind": "text"
                },
                "installation_id": {
                  "kind": "text"
                },
                "schema": {
                  "kind": "text",
                  "constant": "d01.runtime-identity-ref.v3"
                }
              }
            },
            "policy_id": {
              "kind": "text"
            },
            "review_target_block": {
              "kind": "text"
            },
            "task_class": {
              "kind": "text",
              "choices": [
                "artifact_draft",
                "source_note",
                "life_activity"
              ]
            },
            "target_observable": {
              "kind": "text"
            },
            "resolution_rule": {
              "kind": "text"
            },
            "population_scope_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "minimum_verified_outcomes": {
              "kind": "integer"
            },
            "missing_outcome_policy": {
              "kind": "text",
              "choices": [
                "report_known_and_unknown",
                "require_complete_for_threshold"
              ]
            },
            "valid_from": {
              "kind": "number"
            },
            "valid_until": {
              "kind": "number"
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "schema": {
              "kind": "text",
              "constant": "d01.calibration-policy.v1"
            }
          }
        }
      }
    }
  },
  "register_condition_predicate_v1": {
    "label": "登记适用条件",
    "domain": "self",
    "purpose": "consolidation",
    "request": {
      "kind": "object",
      "fields": {
        "value": {
          "kind": "object",
          "fields": {
            "namespace": {
              "kind": "object",
              "fields": {
                "bot_id": {
                  "kind": "text"
                },
                "persona_id": {
                  "kind": "text"
                }
              }
            },
            "predicate_id": {
              "kind": "text"
            },
            "calibration_policy_ref": {
              "kind": "text"
            },
            "task_class": {
              "kind": "text",
              "choices": [
                "artifact_draft",
                "source_note",
                "life_activity"
              ]
            },
            "scope_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "conditions": {
              "kind": "array",
              "item": {
                "kind": "tuple",
                "items": [
                  {
                    "kind": "text",
                    "choices": [
                      "structure_explicit",
                      "materials_complete",
                      "tone_multiple_legal_readings",
                      "long_draft",
                      "local_sample_permitted",
                      "budget_deadline_feasible",
                      "short_draft",
                      "immediate_full_draft",
                      "fact_permission_gap"
                    ]
                  },
                  {
                    "kind": "boolean"
                  }
                ]
              }
            },
            "exclusions": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "valid_from": {
              "kind": "number"
            },
            "valid_until": {
              "kind": "number"
            },
            "schema": {
              "kind": "text",
              "constant": "d01.condition-predicate.v1"
            },
            "rule": {
              "kind": "text",
              "constant": "all_registered_conditions"
            },
            "rollback_predicate_ref": {
              "kind": "text",
              "nullable": true
            }
          }
        }
      }
    }
  },
  "register_simulation_forecast_plan_v1": {
    "label": "登记模拟前预测方案",
    "domain": "self",
    "purpose": "consolidation",
    "request": {
      "kind": "object",
      "fields": {
        "value": {
          "kind": "object",
          "fields": {
            "namespace": {
              "kind": "object",
              "fields": {
                "bot_id": {
                  "kind": "text"
                },
                "persona_id": {
                  "kind": "text"
                }
              }
            },
            "plan_id": {
              "kind": "text"
            },
            "simulation_request_ref": {
              "kind": "text"
            },
            "simulation_activity_id": {
              "kind": "text"
            },
            "baseline_snapshot": {
              "kind": "array",
              "item": {
                "kind": "object",
                "fields": {
                  "key": {
                    "kind": "text"
                  },
                  "revision": {
                    "kind": "integer"
                  }
                }
              }
            },
            "baseline_assumption_ref": {
              "kind": "text"
            },
            "alternative_assumption_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "forecasts": {
              "kind": "array",
              "item": {
                "kind": "object",
                "fields": {
                  "namespace": {
                    "kind": "object",
                    "fields": {
                      "bot_id": {
                        "kind": "text"
                      },
                      "persona_id": {
                        "kind": "text"
                      }
                    }
                  },
                  "prediction_id": {
                    "kind": "text"
                  },
                  "task_class": {
                    "kind": "text",
                    "choices": [
                      "artifact_draft",
                      "source_note",
                      "life_activity"
                    ]
                  },
                  "condition_predicate_ref": {
                    "kind": "text"
                  },
                  "branch_ref": {
                    "kind": "text",
                    "nullable": true
                  },
                  "target_head": {
                    "kind": "object",
                    "fields": {
                      "key": {
                        "kind": "text"
                      },
                      "revision": {
                        "kind": "integer"
                      }
                    }
                  },
                  "target_observable": {
                    "kind": "text"
                  },
                  "predicted_range": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "number"
                      },
                      {
                        "kind": "number"
                      }
                    ],
                    "nullable": true
                  },
                  "predicted_category": {
                    "kind": "text",
                    "nullable": true
                  },
                  "assumption_refs": {
                    "kind": "array",
                    "item": {
                      "kind": "text"
                    }
                  },
                  "assumption_heads": {
                    "kind": "array",
                    "item": {
                      "kind": "object",
                      "fields": {
                        "key": {
                          "kind": "text"
                        },
                        "revision": {
                          "kind": "integer"
                        }
                      }
                    }
                  },
                  "condition_goal_head": {
                    "kind": "object",
                    "fields": {
                      "key": {
                        "kind": "text"
                      },
                      "revision": {
                        "kind": "integer"
                      }
                    }
                  },
                  "condition_goal_revision": {
                    "kind": "integer"
                  },
                  "observer_kind": {
                    "kind": "text"
                  },
                  "resolution_rule": {
                    "kind": "text"
                  },
                  "resolution_target_ref": {
                    "kind": "text"
                  },
                  "expires_at": {
                    "kind": "number"
                  },
                  "registered_at": {
                    "kind": "number"
                  },
                  "source_refs": {
                    "kind": "array",
                    "item": {
                      "kind": "text"
                    }
                  },
                  "schema": {
                    "kind": "text",
                    "constant": "d07.prediction-record.v1"
                  },
                  "content_reality": {
                    "kind": "text",
                    "constant": "forecast"
                  },
                  "producer_kind": {
                    "kind": "text"
                  }
                }
              }
            },
            "declared_at": {
              "kind": "number"
            },
            "valid_until": {
              "kind": "number"
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "schema": {
              "kind": "text",
              "constant": "d07.simulation-forecast-plan.v1"
            },
            "forecast_mode": {
              "kind": "text",
              "constant": "declared_forecast"
            }
          }
        }
      }
    }
  },
  "adopt_current_conditioned_self_v1": {
    "label": "明确采用能力与策略候选",
    "domain": "self",
    "purpose": "consolidation",
    "request": {
      "kind": "object",
      "fields": {
        "candidate_ref": {
          "kind": "text"
        },
        "expected_persona_head": {
          "kind": "object",
          "fields": {
            "key": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            }
          }
        },
        "general_request": {
          "kind": "object",
          "fields": {
            "general_growth_intent_ref": {
              "kind": "text"
            },
            "growth_proposal_ref": {
              "kind": "text"
            },
            "trigger_original_ref": {
              "kind": "text"
            },
            "trial_original_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "counterevidence_query_ref": {
              "kind": "text"
            }
          }
        }
      }
    }
  },
  "rollback_current_conditioned_strategy_v1": {
    "label": "明确回退当前策略",
    "domain": "self",
    "purpose": "consolidation",
    "request": {
      "kind": "object",
      "fields": {
        "candidate_ref": {
          "kind": "text"
        },
        "expected_persona_head": {
          "kind": "object",
          "fields": {
            "key": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            }
          }
        },
        "general_request": {
          "kind": "object",
          "fields": {
            "general_growth_intent_ref": {
              "kind": "text"
            },
            "growth_proposal_ref": {
              "kind": "text"
            },
            "trigger_original_ref": {
              "kind": "text"
            },
            "trial_original_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "counterevidence_query_ref": {
              "kind": "text"
            }
          }
        },
        "rejected_strategy_ref": {
          "kind": "text"
        }
      }
    }
  },
  "adopt_world_assertion_v1": {
    "label": "登记有来源的世界事实",
    "domain": "world",
    "purpose": "consolidation",
    "request": {
      "kind": "object",
      "fields": {
        "assertion": {
          "kind": "object",
          "fields": {
            "assertion_id": {
              "kind": "text"
            },
            "revision_id": {
              "kind": "text"
            },
            "event_version": {
              "kind": "object",
              "fields": {
                "key": {
                  "kind": "text"
                },
                "revision": {
                  "kind": "integer"
                }
              }
            },
            "perspective_version": {
              "kind": "object",
              "fields": {
                "key": {
                  "kind": "text"
                },
                "revision": {
                  "kind": "integer"
                }
              }
            },
            "interpretation_version": {
              "kind": "object",
              "fields": {
                "key": {
                  "kind": "text"
                },
                "revision": {
                  "kind": "integer"
                }
              },
              "nullable": true
            },
            "valid_interval": {
              "kind": "object",
              "fields": {
                "lower": {
                  "kind": "number",
                  "nullable": true
                },
                "upper": {
                  "kind": "number",
                  "nullable": true
                },
                "precision": {
                  "kind": "text",
                  "choices": [
                    "exact",
                    "bounded",
                    "open",
                    "unknown"
                  ]
                }
              }
            },
            "occurred_interval": {
              "kind": "object",
              "fields": {
                "lower": {
                  "kind": "number",
                  "nullable": true
                },
                "upper": {
                  "kind": "number",
                  "nullable": true
                },
                "precision": {
                  "kind": "text",
                  "choices": [
                    "exact",
                    "bounded",
                    "open",
                    "unknown"
                  ]
                }
              }
            },
            "learned_at": {
              "kind": "number"
            },
            "received_at": {
              "kind": "number",
              "nullable": true
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "origin_kind": {
              "kind": "text",
              "choices": [
                "reported",
                "observed",
                "derived",
                "simulated"
              ]
            },
            "reality": {
              "kind": "text",
              "choices": [
                "host_observed",
                "reported",
                "candidate",
                "simulated"
              ]
            },
            "assertion_status": {
              "kind": "text",
              "choices": [
                "asserted",
                "confirmed",
                "disputed",
                "retracted",
                "unknown"
              ]
            },
            "scope": {
              "kind": "text"
            },
            "supersedes_ref": {
              "kind": "text",
              "nullable": true
            },
            "correction_ref": {
              "kind": "text",
              "nullable": true
            },
            "dispute_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "prior_erasure_digest": {
              "kind": "text",
              "nullable": true
            },
            "schema": {
              "kind": "text",
              "constant": "d03.world-assertion-input.v1"
            }
          }
        }
      }
    }
  },
  "relearn_world_assertion_v1": {
    "label": "根据新材料重新学习",
    "domain": "world",
    "purpose": "consolidation",
    "request": {
      "kind": "object",
      "fields": {
        "assertion": {
          "kind": "object",
          "fields": {
            "assertion_id": {
              "kind": "text"
            },
            "revision_id": {
              "kind": "text"
            },
            "event_version": {
              "kind": "object",
              "fields": {
                "key": {
                  "kind": "text"
                },
                "revision": {
                  "kind": "integer"
                }
              }
            },
            "perspective_version": {
              "kind": "object",
              "fields": {
                "key": {
                  "kind": "text"
                },
                "revision": {
                  "kind": "integer"
                }
              }
            },
            "interpretation_version": {
              "kind": "object",
              "fields": {
                "key": {
                  "kind": "text"
                },
                "revision": {
                  "kind": "integer"
                }
              },
              "nullable": true
            },
            "valid_interval": {
              "kind": "object",
              "fields": {
                "lower": {
                  "kind": "number",
                  "nullable": true
                },
                "upper": {
                  "kind": "number",
                  "nullable": true
                },
                "precision": {
                  "kind": "text",
                  "choices": [
                    "exact",
                    "bounded",
                    "open",
                    "unknown"
                  ]
                }
              }
            },
            "occurred_interval": {
              "kind": "object",
              "fields": {
                "lower": {
                  "kind": "number",
                  "nullable": true
                },
                "upper": {
                  "kind": "number",
                  "nullable": true
                },
                "precision": {
                  "kind": "text",
                  "choices": [
                    "exact",
                    "bounded",
                    "open",
                    "unknown"
                  ]
                }
              }
            },
            "learned_at": {
              "kind": "number"
            },
            "received_at": {
              "kind": "number",
              "nullable": true
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "origin_kind": {
              "kind": "text",
              "choices": [
                "reported",
                "observed",
                "derived",
                "simulated"
              ]
            },
            "reality": {
              "kind": "text",
              "choices": [
                "host_observed",
                "reported",
                "candidate",
                "simulated"
              ]
            },
            "assertion_status": {
              "kind": "text",
              "choices": [
                "asserted",
                "confirmed",
                "disputed",
                "retracted",
                "unknown"
              ]
            },
            "scope": {
              "kind": "text"
            },
            "supersedes_ref": {
              "kind": "text",
              "nullable": true
            },
            "correction_ref": {
              "kind": "text",
              "nullable": true
            },
            "dispute_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "prior_erasure_digest": {
              "kind": "text",
              "nullable": true
            },
            "schema": {
              "kind": "text",
              "constant": "d03.world-assertion-input.v1"
            }
          }
        },
        "prior_erasure_ref": {
          "kind": "object",
          "fields": {
            "assertion_commitment": {
              "kind": "text"
            },
            "known_from_sequence": {
              "kind": "integer"
            },
            "payload_digest": {
              "kind": "text"
            }
          }
        }
      }
    }
  },
  "query_world_view_v1": {
    "label": "生成时间与知识截面的世界视图",
    "domain": "world",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "event_time_as_of": {
          "kind": "number"
        },
        "knowledge_as_of": {
          "kind": "integer"
        },
        "perspective_version": {
          "kind": "object",
          "fields": {
            "key": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            }
          }
        },
        "purpose": {
          "kind": "text"
        },
        "audience": {
          "kind": "text"
        },
        "coverage_bound": {
          "kind": "integer"
        },
        "cursor": {
          "kind": "object",
          "fields": {
            "query_digest": {
              "kind": "text"
            },
            "knowledge_watermark": {
              "kind": "integer"
            },
            "after_assertion_commitment": {
              "kind": "text"
            }
          },
          "nullable": true
        }
      }
    }
  },
  "project_world_perspective_v1": {
    "label": "生成已有视图的表达投影",
    "domain": "world",
    "purpose": "expression",
    "request": {
      "kind": "object",
      "fields": {
        "view_version": {
          "kind": "object",
          "fields": {
            "key": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            }
          }
        },
        "communication_grant_version": {
          "kind": "object",
          "fields": {
            "key": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            }
          }
        },
        "scene_ref": {
          "kind": "text"
        },
        "conversation_epoch": {
          "kind": "integer"
        }
      }
    }
  },
  "adopt_long_term_plan_v1": {
    "label": "登记长期计划",
    "domain": "long_window",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "plan": {
          "kind": "object",
          "fields": {
            "namespace": {
              "kind": "object",
              "fields": {
                "bot_id": {
                  "kind": "text"
                },
                "persona_id": {
                  "kind": "text"
                }
              }
            },
            "plan_id": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            },
            "goal_ref": {
              "kind": "text"
            },
            "project_ref": {
              "kind": "text"
            },
            "milestones": {
              "kind": "array",
              "item": {
                "kind": "object",
                "fields": {
                  "milestone_id": {
                    "kind": "text"
                  },
                  "goal_ref": {
                    "kind": "text"
                  },
                  "project_ref": {
                    "kind": "text"
                  },
                  "depends_on": {
                    "kind": "array",
                    "item": {
                      "kind": "text"
                    }
                  },
                  "success_predicate": {
                    "kind": "object",
                    "fields": {
                      "kind": {
                        "kind": "text",
                        "choices": [
                          "artifact_verified",
                          "action_postcondition",
                          "communicated",
                          "recipient_acknowledged",
                          "domain_state",
                          "explicit_confirmation"
                        ]
                      },
                      "observation_provider": {
                        "kind": "text"
                      },
                      "parameters": {
                        "kind": "array",
                        "item": {
                          "kind": "tuple",
                          "items": [
                            {
                              "kind": "text"
                            },
                            {
                              "kind": "text"
                            }
                          ]
                        }
                      },
                      "valid_from": {
                        "kind": "number"
                      },
                      "valid_until": {
                        "kind": "number",
                        "nullable": true
                      }
                    }
                  },
                  "source_refs": {
                    "kind": "array",
                    "item": {
                      "kind": "text"
                    }
                  }
                }
              }
            },
            "current_window_ref": {
              "kind": "text",
              "nullable": true
            },
            "state": {
              "kind": "text",
              "choices": [
                "described",
                "preparing",
                "ready",
                "waiting",
                "paused",
                "stopped",
                "closed"
              ]
            },
            "owner_authorization_original_ref": {
              "kind": "text"
            },
            "owner_authorization_original_digest": {
              "kind": "text"
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "purpose": {
              "kind": "text"
            },
            "audience": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "schema": {
              "kind": "text",
              "constant": "d08.long-term-plan.v1"
            }
          }
        }
      }
    }
  },
  "prepare_joint_window_v1": {
    "label": "准备当前协作窗口",
    "domain": "long_window",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "window": {
          "kind": "object",
          "fields": {
            "namespace": {
              "kind": "object",
              "fields": {
                "bot_id": {
                  "kind": "text"
                },
                "persona_id": {
                  "kind": "text"
                }
              }
            },
            "window_id": {
              "kind": "text"
            },
            "long_term_plan_ref": {
              "kind": "text"
            },
            "long_term_plan_revision": {
              "kind": "integer"
            },
            "window_index": {
              "kind": "integer"
            },
            "prior_window_ref": {
              "kind": "text",
              "nullable": true
            },
            "node_drafts": {
              "kind": "array",
              "item": {
                "kind": "object",
                "fields": {
                  "node_id": {
                    "kind": "text"
                  },
                  "party_scope": {
                    "kind": "text"
                  },
                  "executor_kind": {
                    "kind": "text",
                    "choices": [
                      "source_note",
                      "draft_file",
                      "contact",
                      "external"
                    ]
                  },
                  "typed_request_ref": {
                    "kind": "text"
                  },
                  "typed_request_digest": {
                    "kind": "text"
                  },
                  "typed_input_original_digest": {
                    "kind": "text"
                  },
                  "goal_ref": {
                    "kind": "text"
                  },
                  "project_ref": {
                    "kind": "text"
                  },
                  "recipe_ref": {
                    "kind": "text"
                  },
                  "recipe_revision": {
                    "kind": "integer"
                  },
                  "target_ref": {
                    "kind": "text"
                  },
                  "source_refs": {
                    "kind": "array",
                    "item": {
                      "kind": "text"
                    }
                  },
                  "success_predicate": {
                    "kind": "object",
                    "fields": {
                      "kind": {
                        "kind": "text",
                        "choices": [
                          "artifact_verified",
                          "action_postcondition",
                          "communicated",
                          "recipient_acknowledged",
                          "domain_state",
                          "explicit_confirmation"
                        ]
                      },
                      "observation_provider": {
                        "kind": "text"
                      },
                      "parameters": {
                        "kind": "array",
                        "item": {
                          "kind": "tuple",
                          "items": [
                            {
                              "kind": "text"
                            },
                            {
                              "kind": "text"
                            }
                          ]
                        }
                      },
                      "valid_from": {
                        "kind": "number"
                      },
                      "valid_until": {
                        "kind": "number",
                        "nullable": true
                      }
                    }
                  },
                  "parent_grant_ref": {
                    "kind": "text"
                  },
                  "parent_grant_digest": {
                    "kind": "text"
                  },
                  "original_deadline_utc": {
                    "kind": "number"
                  },
                  "cancellation_point": {
                    "kind": "boolean"
                  },
                  "cancellation_ref": {
                    "kind": "text"
                  },
                  "compensation_ref": {
                    "kind": "text",
                    "nullable": true
                  },
                  "resource_commitment": {
                    "kind": "text"
                  },
                  "purpose": {
                    "kind": "text"
                  },
                  "audience": {
                    "kind": "array",
                    "item": {
                      "kind": "text"
                    }
                  }
                }
              }
            },
            "candidate_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "draft_terms_original_ref": {
              "kind": "text"
            },
            "draft_terms_original_digest": {
              "kind": "text"
            },
            "final_joint_plan_ref": {
              "kind": "text",
              "nullable": true
            },
            "final_joint_plan_revision": {
              "kind": "integer",
              "nullable": true
            },
            "final_binding_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "final_terms_original_ref": {
              "kind": "text",
              "nullable": true
            },
            "final_terms_original_digest": {
              "kind": "text",
              "nullable": true
            },
            "party_acceptance_original_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "state": {
              "kind": "text",
              "choices": [
                "described",
                "preparing",
                "ready",
                "waiting",
                "paused",
                "stopped",
                "closed"
              ]
            },
            "original_deadline_utc": {
              "kind": "number"
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "schema": {
              "kind": "text",
              "constant": "d08.joint-window.v1"
            }
          }
        },
        "strategy_projection_ref": {
          "kind": "text",
          "nullable": true
        },
        "strategy_projection_digest": {
          "kind": "text",
          "nullable": true
        }
      }
    }
  },
  "enter_current_joint_window_v1": {
    "label": "进入当前窗口",
    "domain": "long_window",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "window_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        }
      }
    }
  },
  "finalize_current_joint_window_v1": {
    "label": "登记最终条款与各方接受",
    "domain": "long_window",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "window_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        },
        "joint_plan_ref": {
          "kind": "text"
        },
        "joint_plan_revision": {
          "kind": "integer"
        },
        "final_terms_original_ref": {
          "kind": "text"
        },
        "final_terms_original_digest": {
          "kind": "text"
        },
        "binding_refs": {
          "kind": "array",
          "item": {
            "kind": "text"
          }
        },
        "party_acceptance_original_refs": {
          "kind": "array",
          "item": {
            "kind": "text"
          }
        }
      }
    }
  },
  "advance_long_term_window_v1": {
    "label": "凭已核验结果推进窗口",
    "domain": "long_window",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "previous_window_ref": {
          "kind": "text"
        },
        "previous_window_revision": {
          "kind": "integer"
        },
        "next_window_ref": {
          "kind": "text"
        },
        "next_window_revision": {
          "kind": "integer"
        },
        "milestone_evidence_original_refs": {
          "kind": "array",
          "item": {
            "kind": "text"
          }
        },
        "joint_qualification_original_ref": {
          "kind": "text"
        },
        "joint_qualification_original_digest": {
          "kind": "text"
        },
        "result_versions_digest": {
          "kind": "text"
        }
      }
    }
  },
  "pause_long_term_plan_v1": {
    "label": "暂停长期计划",
    "domain": "long_window",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "plan_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        }
      }
    }
  },
  "resume_long_term_plan_v1": {
    "label": "恢复长期计划",
    "domain": "long_window",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "plan_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        },
        "pause_original_ref": {
          "kind": "text"
        }
      }
    }
  },
  "stop_long_term_plan_v1": {
    "label": "停止长期计划",
    "domain": "long_window",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "plan_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        }
      }
    }
  },
  "create_habit_policy_v1": {
    "label": "创建习惯政策",
    "domain": "habit",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "definition": {
          "kind": "object",
          "fields": {
            "namespace": {
              "kind": "object",
              "fields": {
                "bot_id": {
                  "kind": "text"
                },
                "persona_id": {
                  "kind": "text"
                }
              }
            },
            "policy_id": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            },
            "project_ref": {
              "kind": "text"
            },
            "recipe_ref": {
              "kind": "text"
            },
            "recipe_revision": {
              "kind": "integer"
            },
            "executor_kind": {
              "kind": "text",
              "choices": [
                "source_note",
                "draft_file"
              ]
            },
            "cue_predicate": {
              "kind": "object",
              "fields": {
                "kind": {
                  "kind": "text",
                  "choices": [
                    "artifact_verified",
                    "action_postcondition",
                    "communicated",
                    "recipient_acknowledged",
                    "domain_state",
                    "explicit_confirmation"
                  ]
                },
                "observation_provider": {
                  "kind": "text"
                },
                "parameters": {
                  "kind": "array",
                  "item": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "text"
                      },
                      {
                        "kind": "text"
                      }
                    ]
                  }
                },
                "valid_from": {
                  "kind": "number"
                },
                "valid_until": {
                  "kind": "number",
                  "nullable": true
                }
              }
            },
            "window_anchor_utc": {
              "kind": "number"
            },
            "window_seconds": {
              "kind": "number"
            },
            "execution_seconds": {
              "kind": "number"
            },
            "minimum_interval_seconds": {
              "kind": "number"
            },
            "maximum_occurrences_per_window": {
              "kind": "integer"
            },
            "parent_root_grant_ref": {
              "kind": "text"
            },
            "parent_root_grant_id": {
              "kind": "text"
            },
            "parent_root_grant_version": {
              "kind": "integer"
            },
            "parent_root_grant_digest": {
              "kind": "text"
            },
            "original_valid_until_utc": {
              "kind": "number"
            },
            "miss_policy": {
              "kind": "text",
              "choices": [
                "skipped",
                "wait",
                "reschedule-required"
              ]
            },
            "stop_predicate": {
              "kind": "object",
              "fields": {
                "kind": {
                  "kind": "text",
                  "choices": [
                    "artifact_verified",
                    "action_postcondition",
                    "communicated",
                    "recipient_acknowledged",
                    "domain_state",
                    "explicit_confirmation"
                  ]
                },
                "observation_provider": {
                  "kind": "text"
                },
                "parameters": {
                  "kind": "array",
                  "item": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "text"
                      },
                      {
                        "kind": "text"
                      }
                    ]
                  }
                },
                "valid_from": {
                  "kind": "number"
                },
                "valid_until": {
                  "kind": "number",
                  "nullable": true
                }
              }
            },
            "state": {
              "kind": "text",
              "choices": [
                "enabled",
                "paused",
                "stopped",
                "superseded"
              ]
            },
            "cancellation_generation": {
              "kind": "integer"
            },
            "purpose": {
              "kind": "text"
            },
            "audience": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "target_ref": {
              "kind": "text"
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "source_note_input": {
              "kind": "object",
              "fields": {
                "source_ref": {
                  "kind": "text"
                },
                "source_revision": {
                  "kind": "integer"
                },
                "source_digest": {
                  "kind": "text"
                },
                "role_binding_ref": {
                  "kind": "text"
                },
                "role_binding_revision": {
                  "kind": "integer"
                },
                "role_binding_digest": {
                  "kind": "text"
                },
                "instantiate_occurrence_context": {
                  "kind": "boolean"
                },
                "recipe_version": {
                  "kind": "text"
                }
              },
              "nullable": true
            },
            "schema": {
              "kind": "text",
              "constant": "d10.habit-policy-definition.v1"
            }
          }
        }
      }
    }
  },
  "revise_habit_policy_v1": {
    "label": "修订习惯政策",
    "domain": "habit",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "policy_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        },
        "definition": {
          "kind": "object",
          "fields": {
            "namespace": {
              "kind": "object",
              "fields": {
                "bot_id": {
                  "kind": "text"
                },
                "persona_id": {
                  "kind": "text"
                }
              }
            },
            "policy_id": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            },
            "project_ref": {
              "kind": "text"
            },
            "recipe_ref": {
              "kind": "text"
            },
            "recipe_revision": {
              "kind": "integer"
            },
            "executor_kind": {
              "kind": "text",
              "choices": [
                "source_note",
                "draft_file"
              ]
            },
            "cue_predicate": {
              "kind": "object",
              "fields": {
                "kind": {
                  "kind": "text",
                  "choices": [
                    "artifact_verified",
                    "action_postcondition",
                    "communicated",
                    "recipient_acknowledged",
                    "domain_state",
                    "explicit_confirmation"
                  ]
                },
                "observation_provider": {
                  "kind": "text"
                },
                "parameters": {
                  "kind": "array",
                  "item": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "text"
                      },
                      {
                        "kind": "text"
                      }
                    ]
                  }
                },
                "valid_from": {
                  "kind": "number"
                },
                "valid_until": {
                  "kind": "number",
                  "nullable": true
                }
              }
            },
            "window_anchor_utc": {
              "kind": "number"
            },
            "window_seconds": {
              "kind": "number"
            },
            "execution_seconds": {
              "kind": "number"
            },
            "minimum_interval_seconds": {
              "kind": "number"
            },
            "maximum_occurrences_per_window": {
              "kind": "integer"
            },
            "parent_root_grant_ref": {
              "kind": "text"
            },
            "parent_root_grant_id": {
              "kind": "text"
            },
            "parent_root_grant_version": {
              "kind": "integer"
            },
            "parent_root_grant_digest": {
              "kind": "text"
            },
            "original_valid_until_utc": {
              "kind": "number"
            },
            "miss_policy": {
              "kind": "text",
              "choices": [
                "skipped",
                "wait",
                "reschedule-required"
              ]
            },
            "stop_predicate": {
              "kind": "object",
              "fields": {
                "kind": {
                  "kind": "text",
                  "choices": [
                    "artifact_verified",
                    "action_postcondition",
                    "communicated",
                    "recipient_acknowledged",
                    "domain_state",
                    "explicit_confirmation"
                  ]
                },
                "observation_provider": {
                  "kind": "text"
                },
                "parameters": {
                  "kind": "array",
                  "item": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "text"
                      },
                      {
                        "kind": "text"
                      }
                    ]
                  }
                },
                "valid_from": {
                  "kind": "number"
                },
                "valid_until": {
                  "kind": "number",
                  "nullable": true
                }
              }
            },
            "state": {
              "kind": "text",
              "choices": [
                "enabled",
                "paused",
                "stopped",
                "superseded"
              ]
            },
            "cancellation_generation": {
              "kind": "integer"
            },
            "purpose": {
              "kind": "text"
            },
            "audience": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "target_ref": {
              "kind": "text"
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "source_note_input": {
              "kind": "object",
              "fields": {
                "source_ref": {
                  "kind": "text"
                },
                "source_revision": {
                  "kind": "integer"
                },
                "source_digest": {
                  "kind": "text"
                },
                "role_binding_ref": {
                  "kind": "text"
                },
                "role_binding_revision": {
                  "kind": "integer"
                },
                "role_binding_digest": {
                  "kind": "text"
                },
                "instantiate_occurrence_context": {
                  "kind": "boolean"
                },
                "recipe_version": {
                  "kind": "text"
                }
              },
              "nullable": true
            },
            "schema": {
              "kind": "text",
              "constant": "d10.habit-policy-definition.v1"
            }
          }
        }
      }
    }
  },
  "pause_habit_policy_v1": {
    "label": "暂停习惯政策",
    "domain": "habit",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "policy_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        },
        "definition": {
          "kind": "object",
          "fields": {
            "namespace": {
              "kind": "object",
              "fields": {
                "bot_id": {
                  "kind": "text"
                },
                "persona_id": {
                  "kind": "text"
                }
              }
            },
            "policy_id": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            },
            "project_ref": {
              "kind": "text"
            },
            "recipe_ref": {
              "kind": "text"
            },
            "recipe_revision": {
              "kind": "integer"
            },
            "executor_kind": {
              "kind": "text",
              "choices": [
                "source_note",
                "draft_file"
              ]
            },
            "cue_predicate": {
              "kind": "object",
              "fields": {
                "kind": {
                  "kind": "text",
                  "choices": [
                    "artifact_verified",
                    "action_postcondition",
                    "communicated",
                    "recipient_acknowledged",
                    "domain_state",
                    "explicit_confirmation"
                  ]
                },
                "observation_provider": {
                  "kind": "text"
                },
                "parameters": {
                  "kind": "array",
                  "item": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "text"
                      },
                      {
                        "kind": "text"
                      }
                    ]
                  }
                },
                "valid_from": {
                  "kind": "number"
                },
                "valid_until": {
                  "kind": "number",
                  "nullable": true
                }
              }
            },
            "window_anchor_utc": {
              "kind": "number"
            },
            "window_seconds": {
              "kind": "number"
            },
            "execution_seconds": {
              "kind": "number"
            },
            "minimum_interval_seconds": {
              "kind": "number"
            },
            "maximum_occurrences_per_window": {
              "kind": "integer"
            },
            "parent_root_grant_ref": {
              "kind": "text"
            },
            "parent_root_grant_id": {
              "kind": "text"
            },
            "parent_root_grant_version": {
              "kind": "integer"
            },
            "parent_root_grant_digest": {
              "kind": "text"
            },
            "original_valid_until_utc": {
              "kind": "number"
            },
            "miss_policy": {
              "kind": "text",
              "choices": [
                "skipped",
                "wait",
                "reschedule-required"
              ]
            },
            "stop_predicate": {
              "kind": "object",
              "fields": {
                "kind": {
                  "kind": "text",
                  "choices": [
                    "artifact_verified",
                    "action_postcondition",
                    "communicated",
                    "recipient_acknowledged",
                    "domain_state",
                    "explicit_confirmation"
                  ]
                },
                "observation_provider": {
                  "kind": "text"
                },
                "parameters": {
                  "kind": "array",
                  "item": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "text"
                      },
                      {
                        "kind": "text"
                      }
                    ]
                  }
                },
                "valid_from": {
                  "kind": "number"
                },
                "valid_until": {
                  "kind": "number",
                  "nullable": true
                }
              }
            },
            "state": {
              "kind": "text",
              "choices": [
                "enabled",
                "paused",
                "stopped",
                "superseded"
              ]
            },
            "cancellation_generation": {
              "kind": "integer"
            },
            "purpose": {
              "kind": "text"
            },
            "audience": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "target_ref": {
              "kind": "text"
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "source_note_input": {
              "kind": "object",
              "fields": {
                "source_ref": {
                  "kind": "text"
                },
                "source_revision": {
                  "kind": "integer"
                },
                "source_digest": {
                  "kind": "text"
                },
                "role_binding_ref": {
                  "kind": "text"
                },
                "role_binding_revision": {
                  "kind": "integer"
                },
                "role_binding_digest": {
                  "kind": "text"
                },
                "instantiate_occurrence_context": {
                  "kind": "boolean"
                },
                "recipe_version": {
                  "kind": "text"
                }
              },
              "nullable": true
            },
            "schema": {
              "kind": "text",
              "constant": "d10.habit-policy-definition.v1"
            }
          }
        }
      }
    }
  },
  "resume_habit_policy_v1": {
    "label": "恢复习惯政策",
    "domain": "habit",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "policy_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        },
        "definition": {
          "kind": "object",
          "fields": {
            "namespace": {
              "kind": "object",
              "fields": {
                "bot_id": {
                  "kind": "text"
                },
                "persona_id": {
                  "kind": "text"
                }
              }
            },
            "policy_id": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            },
            "project_ref": {
              "kind": "text"
            },
            "recipe_ref": {
              "kind": "text"
            },
            "recipe_revision": {
              "kind": "integer"
            },
            "executor_kind": {
              "kind": "text",
              "choices": [
                "source_note",
                "draft_file"
              ]
            },
            "cue_predicate": {
              "kind": "object",
              "fields": {
                "kind": {
                  "kind": "text",
                  "choices": [
                    "artifact_verified",
                    "action_postcondition",
                    "communicated",
                    "recipient_acknowledged",
                    "domain_state",
                    "explicit_confirmation"
                  ]
                },
                "observation_provider": {
                  "kind": "text"
                },
                "parameters": {
                  "kind": "array",
                  "item": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "text"
                      },
                      {
                        "kind": "text"
                      }
                    ]
                  }
                },
                "valid_from": {
                  "kind": "number"
                },
                "valid_until": {
                  "kind": "number",
                  "nullable": true
                }
              }
            },
            "window_anchor_utc": {
              "kind": "number"
            },
            "window_seconds": {
              "kind": "number"
            },
            "execution_seconds": {
              "kind": "number"
            },
            "minimum_interval_seconds": {
              "kind": "number"
            },
            "maximum_occurrences_per_window": {
              "kind": "integer"
            },
            "parent_root_grant_ref": {
              "kind": "text"
            },
            "parent_root_grant_id": {
              "kind": "text"
            },
            "parent_root_grant_version": {
              "kind": "integer"
            },
            "parent_root_grant_digest": {
              "kind": "text"
            },
            "original_valid_until_utc": {
              "kind": "number"
            },
            "miss_policy": {
              "kind": "text",
              "choices": [
                "skipped",
                "wait",
                "reschedule-required"
              ]
            },
            "stop_predicate": {
              "kind": "object",
              "fields": {
                "kind": {
                  "kind": "text",
                  "choices": [
                    "artifact_verified",
                    "action_postcondition",
                    "communicated",
                    "recipient_acknowledged",
                    "domain_state",
                    "explicit_confirmation"
                  ]
                },
                "observation_provider": {
                  "kind": "text"
                },
                "parameters": {
                  "kind": "array",
                  "item": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "text"
                      },
                      {
                        "kind": "text"
                      }
                    ]
                  }
                },
                "valid_from": {
                  "kind": "number"
                },
                "valid_until": {
                  "kind": "number",
                  "nullable": true
                }
              }
            },
            "state": {
              "kind": "text",
              "choices": [
                "enabled",
                "paused",
                "stopped",
                "superseded"
              ]
            },
            "cancellation_generation": {
              "kind": "integer"
            },
            "purpose": {
              "kind": "text"
            },
            "audience": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "target_ref": {
              "kind": "text"
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "source_note_input": {
              "kind": "object",
              "fields": {
                "source_ref": {
                  "kind": "text"
                },
                "source_revision": {
                  "kind": "integer"
                },
                "source_digest": {
                  "kind": "text"
                },
                "role_binding_ref": {
                  "kind": "text"
                },
                "role_binding_revision": {
                  "kind": "integer"
                },
                "role_binding_digest": {
                  "kind": "text"
                },
                "instantiate_occurrence_context": {
                  "kind": "boolean"
                },
                "recipe_version": {
                  "kind": "text"
                }
              },
              "nullable": true
            },
            "schema": {
              "kind": "text",
              "constant": "d10.habit-policy-definition.v1"
            }
          }
        }
      }
    }
  },
  "stop_habit_policy_v1": {
    "label": "停止习惯政策",
    "domain": "habit",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "policy_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        },
        "definition": {
          "kind": "object",
          "fields": {
            "namespace": {
              "kind": "object",
              "fields": {
                "bot_id": {
                  "kind": "text"
                },
                "persona_id": {
                  "kind": "text"
                }
              }
            },
            "policy_id": {
              "kind": "text"
            },
            "revision": {
              "kind": "integer"
            },
            "project_ref": {
              "kind": "text"
            },
            "recipe_ref": {
              "kind": "text"
            },
            "recipe_revision": {
              "kind": "integer"
            },
            "executor_kind": {
              "kind": "text",
              "choices": [
                "source_note",
                "draft_file"
              ]
            },
            "cue_predicate": {
              "kind": "object",
              "fields": {
                "kind": {
                  "kind": "text",
                  "choices": [
                    "artifact_verified",
                    "action_postcondition",
                    "communicated",
                    "recipient_acknowledged",
                    "domain_state",
                    "explicit_confirmation"
                  ]
                },
                "observation_provider": {
                  "kind": "text"
                },
                "parameters": {
                  "kind": "array",
                  "item": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "text"
                      },
                      {
                        "kind": "text"
                      }
                    ]
                  }
                },
                "valid_from": {
                  "kind": "number"
                },
                "valid_until": {
                  "kind": "number",
                  "nullable": true
                }
              }
            },
            "window_anchor_utc": {
              "kind": "number"
            },
            "window_seconds": {
              "kind": "number"
            },
            "execution_seconds": {
              "kind": "number"
            },
            "minimum_interval_seconds": {
              "kind": "number"
            },
            "maximum_occurrences_per_window": {
              "kind": "integer"
            },
            "parent_root_grant_ref": {
              "kind": "text"
            },
            "parent_root_grant_id": {
              "kind": "text"
            },
            "parent_root_grant_version": {
              "kind": "integer"
            },
            "parent_root_grant_digest": {
              "kind": "text"
            },
            "original_valid_until_utc": {
              "kind": "number"
            },
            "miss_policy": {
              "kind": "text",
              "choices": [
                "skipped",
                "wait",
                "reschedule-required"
              ]
            },
            "stop_predicate": {
              "kind": "object",
              "fields": {
                "kind": {
                  "kind": "text",
                  "choices": [
                    "artifact_verified",
                    "action_postcondition",
                    "communicated",
                    "recipient_acknowledged",
                    "domain_state",
                    "explicit_confirmation"
                  ]
                },
                "observation_provider": {
                  "kind": "text"
                },
                "parameters": {
                  "kind": "array",
                  "item": {
                    "kind": "tuple",
                    "items": [
                      {
                        "kind": "text"
                      },
                      {
                        "kind": "text"
                      }
                    ]
                  }
                },
                "valid_from": {
                  "kind": "number"
                },
                "valid_until": {
                  "kind": "number",
                  "nullable": true
                }
              }
            },
            "state": {
              "kind": "text",
              "choices": [
                "enabled",
                "paused",
                "stopped",
                "superseded"
              ]
            },
            "cancellation_generation": {
              "kind": "integer"
            },
            "purpose": {
              "kind": "text"
            },
            "audience": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "target_ref": {
              "kind": "text"
            },
            "source_refs": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "source_note_input": {
              "kind": "object",
              "fields": {
                "source_ref": {
                  "kind": "text"
                },
                "source_revision": {
                  "kind": "integer"
                },
                "source_digest": {
                  "kind": "text"
                },
                "role_binding_ref": {
                  "kind": "text"
                },
                "role_binding_revision": {
                  "kind": "integer"
                },
                "role_binding_digest": {
                  "kind": "text"
                },
                "instantiate_occurrence_context": {
                  "kind": "boolean"
                },
                "recipe_version": {
                  "kind": "text"
                }
              },
              "nullable": true
            },
            "schema": {
              "kind": "text",
              "constant": "d10.habit-policy-definition.v1"
            }
          }
        }
      }
    }
  },
  "register_habit_occurrence_v1": {
    "label": "登记实际触发原件",
    "domain": "habit",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "policy_ref": {
          "kind": "text"
        },
        "expected_policy_revision": {
          "kind": "integer"
        },
        "cue_original_ref": {
          "kind": "text"
        },
        "cue_original_digest": {
          "kind": "text"
        }
      }
    }
  },
  "qualify_habit_occurrence_v1": {
    "label": "核验本次习惯资格",
    "domain": "habit",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "occurrence_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        }
      }
    }
  },
  "record_habit_miss_v1": {
    "label": "记录本次错过",
    "domain": "habit",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "occurrence_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        },
        "reason_ref": {
          "kind": "text"
        }
      }
    }
  },
  "adopt_habit_outcome_v1": {
    "label": "采用实际习惯结果",
    "domain": "habit",
    "purpose": "context",
    "request": {
      "kind": "object",
      "fields": {
        "occurrence_ref": {
          "kind": "text"
        },
        "expected_revision": {
          "kind": "integer"
        },
        "life_progress_ref": {
          "kind": "text"
        },
        "life_progress_revision": {
          "kind": "integer"
        },
        "life_outcome_original_ref": {
          "kind": "text"
        },
        "actual_terminal_original_ref": {
          "kind": "text"
        },
        "accounting_original_refs": {
          "kind": "array",
          "item": {
            "kind": "text"
          }
        },
        "encoding_trigger_ref": {
          "kind": "text"
        },
        "growth_trigger_ref": {
          "kind": "text"
        }
      }
    }
  }
} satisfies Record<string,{label:string;domain:Beta1Domain;purpose:'context'|'consolidation'|'expression';request:EditorSpec}>
export type Beta1Kind=keyof typeof BETA1_OPERATIONS
export type Beta1Domain='self'|'world'|'habit'|'long_window'
export const CREATOR_FIELDS:Record<string,EditorSpec>={
  "d01.persona_plan": {
    "kind": "object",
    "fields": {
      "plan_id": {
        "kind": "text"
      },
      "namespace": {
        "kind": "object",
        "fields": {
          "bot_id": {
            "kind": "text"
          },
          "persona_id": {
            "kind": "text"
          }
        }
      },
      "version": {
        "kind": "integer"
      },
      "authored": {
        "kind": "boolean"
      },
      "blocks": {
        "kind": "array",
        "item": {
          "kind": "object",
          "fields": {
            "block_id": {
              "kind": "text"
            },
            "kind": {
              "kind": "text",
              "choices": [
                "semantic_identity",
                "value",
                "trait",
                "preference",
                "strategy",
                "self_knowledge"
              ]
            },
            "claim": {
              "kind": "text"
            },
            "plasticity": {
              "kind": "text",
              "choices": [
                "read_only",
                "growth",
                "authored_only"
              ]
            }
          }
        }
      },
      "values": {
        "kind": "array",
        "item": {
          "kind": "object",
          "fields": {
            "rule_id": {
              "kind": "text"
            },
            "label": {
              "kind": "text"
            },
            "applies_to": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "supports_candidates": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            },
            "rejects_candidates": {
              "kind": "array",
              "item": {
                "kind": "text"
              }
            }
          }
        }
      }
    }
  },
  "d02.body_profile": {
    "kind": "object",
    "fields": {
      "profile_id": {
        "kind": "text"
      },
      "namespace": {
        "kind": "object",
        "fields": {
          "bot_id": {
            "kind": "text"
          },
          "persona_id": {
            "kind": "text"
          }
        }
      },
      "version": {
        "kind": "integer"
      },
      "applicable_axes": {
        "kind": "array",
        "item": {
          "kind": "text"
        }
      },
      "work_kinds": {
        "kind": "array",
        "item": {
          "kind": "text"
        }
      }
    }
  },
  "d03.context_scheme": {
    "kind": "object",
    "fields": {
      "schema": {
        "kind": "text",
        "constant": "d03.context.scheme.v1"
      },
      "roles": {
        "kind": "array",
        "item": {
          "kind": "text"
        }
      },
      "norms": {
        "kind": "array",
        "item": {
          "kind": "text"
        }
      }
    }
  },
  "d04.affect_scheme": {
    "kind": "object",
    "fields": {
      "schema": {
        "kind": "text",
        "constant": "d04.affect.scheme.v1"
      },
      "scheme_version": {
        "kind": "text"
      },
      "operator_version": {
        "kind": "text"
      },
      "parameter_version": {
        "kind": "text"
      },
      "coupling_version": {
        "kind": "text"
      },
      "axes": {
        "kind": "array",
        "item": {
          "kind": "object",
          "fields": {
            "axis_id": {
              "kind": "text"
            },
            "unit": {
              "kind": "text"
            },
            "meaning": {
              "kind": "text"
            }
          }
        }
      },
      "parameter_bounds": {
        "kind": "array",
        "item": {
          "kind": "tuple",
          "items": [
            {
              "kind": "text"
            },
            {
              "kind": "number"
            },
            {
              "kind": "number"
            }
          ]
        }
      }
    }
  },
  "d05.relationship_scheme": {
    "kind": "object",
    "fields": {
      "schema": {
        "kind": "text",
        "constant": "d05.relationship.scheme.v1"
      },
      "dimensions": {
        "kind": "array",
        "item": {
          "kind": "text"
        }
      },
      "contribution_semantics": {
        "kind": "array",
        "item": {
          "kind": "text"
        }
      }
    }
  },
  "d06.encoding_projection_policy": {
    "kind": "object",
    "fields": {
      "schema": {
        "kind": "text",
        "constant": "d06.encoding_projection_policy.v1"
      },
      "policy_ref": {
        "kind": "text"
      },
      "policy_version": {
        "kind": "text"
      },
      "salience_gain": {
        "kind": "number"
      },
      "tone_magnitude_gain": {
        "kind": "number"
      },
      "neutral_salience": {
        "kind": "number"
      }
    }
  },
  "d07.attention_policy": {
    "kind": "object",
    "fields": {
      "relevance_weight": {
        "kind": "number"
      },
      "urgency_weight": {
        "kind": "number"
      },
      "information_weight": {
        "kind": "number"
      },
      "persona_weight": {
        "kind": "number"
      },
      "emotion_weight": {
        "kind": "number"
      },
      "waiting_weight": {
        "kind": "number"
      },
      "switch_cost_weight": {
        "kind": "number"
      },
      "fatigue_cost_weight": {
        "kind": "number"
      },
      "served_cost_weight": {
        "kind": "number"
      },
      "primary_limit": {
        "kind": "integer"
      },
      "auxiliary_limit": {
        "kind": "integer"
      },
      "policy_version": {
        "kind": "text"
      }
    }
  },
  "d08.action_schemas": {
    "kind": "array",
    "item": {
      "kind": "object",
      "fields": {
        "schema_id": {
          "kind": "text"
        },
        "action_kind": {
          "kind": "text"
        },
        "proactive": {
          "kind": "boolean"
        },
        "required_checks": {
          "kind": "array",
          "item": {
            "kind": "object",
            "fields": {
              "check_kind": {
                "kind": "text"
              },
              "provider_id": {
                "kind": "text"
              },
              "subject_ref": {
                "kind": "text"
              },
              "action_ref": {
                "kind": "text"
              },
              "purpose": {
                "kind": "text"
              },
              "criteria_version": {
                "kind": "text"
              },
              "required_input_versions": {
                "kind": "array",
                "item": {
                  "kind": "object",
                  "fields": {
                    "ref": {
                      "kind": "text"
                    },
                    "version": {
                      "kind": "integer"
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  },
  "d09.expression_policy": {
    "kind": "object",
    "fields": {
      "schema": {
        "kind": "text",
        "constant": "d09.expression_policy.v1"
      },
      "policy_ref": {
        "kind": "text"
      },
      "policy_version": {
        "kind": "text"
      },
      "max_visible_chars": {
        "kind": "integer"
      }
    }
  },
  "d10.activity_recipe": {
    "kind": "object",
    "fields": {
      "recipe_id": {
        "kind": "text"
      },
      "version": {
        "kind": "integer"
      },
      "reality": {
        "kind": "text",
        "choices": [
          "real_execution",
          "role_simulation"
        ]
      },
      "allowed_steps": {
        "kind": "array",
        "item": {
          "kind": "text"
        }
      },
      "preemptible": {
        "kind": "boolean"
      }
    }
  }
}
export function emptyValue(spec:EditorSpec,scope=''):unknown{
 if(spec.nullable)return null
 if(spec.constant!==undefined)return spec.constant
 if(spec.kind==='object'){
  const value=Object.fromEntries(Object.entries(spec.fields??{}).map(([key,field])=>[key,emptyValue(field,scope)]))
  if(Object.keys(value).join('|')==='bot_id|persona_id'&&scope){const [bot,persona]=scope.split('/');value.bot_id=bot;value.persona_id=persona}
  return value
 }
 if(spec.kind==='array')return []
 if(spec.kind==='tuple')return (spec.items??[]).map(item=>emptyValue(item,scope))
 return spec.kind==='boolean'?false:spec.kind==='text'?'':null
}
export function validateEditorValue(spec:EditorSpec,value:unknown,path='请求'):void{
 if(spec.nullable&&value===null)return
 if(spec.choices&&!spec.choices.includes(String(value)))throw new Error(path+' 需要选择已登记的选项。')
 if(spec.constant!==undefined){if(value!==spec.constant)throw new Error(path+' 的协议常量已变化，请重新读取。');return}
 if(spec.kind==='object'){
  const fields=spec.fields??{}
  if(!hasFields(value,Object.keys(fields)))throw new Error(path+' 的结构不匹配，需后端提供对应字段协议。')
  for(const [key,field]of Object.entries(fields))validateEditorValue(field,value[key],path+'.'+key)
 }else if(spec.kind==='array'||spec.kind==='tuple'){
  if(!Array.isArray(value)||spec.kind==='tuple'&&value.length!==spec.items?.length)throw new Error(path+' 的列表结构不匹配。')
  value.forEach((item,index)=>validateEditorValue(spec.kind==='array'?spec.item! : spec.items![index],item,path+'['+(index+1)+']'))
 }else if(spec.kind==='text'?!isText(value):spec.kind==='boolean'?typeof value!=='boolean':typeof value!=='number'||!Number.isFinite(value)||spec.kind==='integer'&&!Number.isSafeInteger(value))throw new Error('请填写 '+path+' 的实际'+(spec.kind==='text'?'文本或引用':spec.kind==='integer'?'整数':spec.kind==='boolean'?'布尔值':'数值')+'。')
}
export interface Beta1Input{activity_id:string;audience_ref:string;parent_budget_lease_ref:string;request:Record<string,unknown>}
export interface Beta1Attempt{scope:string;kind:Beta1Kind;input:Beta1Input;operationId:string}
export const pendingBeta1Attempts=new Map<string,Beta1Attempt>()
export interface Beta1Receipt{operationId:string;action:string;inputDigest:string;originalDigest:string}
export function validateBeta1Input(kind:Beta1Kind,value:Beta1Input){
 if(!Object.hasOwn(BETA1_OPERATIONS,kind)||!hasFields(value,['activity_id','audience_ref','parent_budget_lease_ref','request'])||![value.activity_id,value.audience_ref,value.parent_budget_lease_ref].every(isText))throw new Error('请填写原 activity、受众与父预算引用。')
 validateEditorValue(BETA1_OPERATIONS[kind].request as EditorSpec,value.request)
 return value
}
export function validateBeta1Receipt(value:unknown,kind:Beta1Kind,id:string):Beta1Receipt{
 if(!hasFields(value,['schema','operation_id','action','input_digest','original_digest','original'])||value.schema!=='d12.domain-operation-receipt.v1'||value.operation_id!==id||value.action!=='domain_'+kind||!isRecord(value.original)||value.original.operation_id!==id||![value.input_digest,value.original_digest].every(item=>typeof item==='string'&&/^[0-9a-f]{64}$/.test(item)))throw new Error('领域操作回执不匹配，本次结果尚未确认。')
 return{operationId:id,action:value.action,inputDigest:value.input_digest as string,originalDigest:value.original_digest as string}
}
export interface Beta1State{scope:string;operationId:string;domain:Exclude<Beta1Domain,'self'>;items:{ref:string;type_name:string;revision:number;state:string;source_refs:string[];related_refs:string[];reason_codes:string[];managed_nodes?:{node_id:string;executor_kind:'source_note'|'draft_file'|'contact'}[]}[];coverage:'complete'|'partial'|'unavailable';missing_inputs:string[]}
export function validateBeta1State(value:unknown,scope:string,domain:Exclude<Beta1Domain,'self'>,id:string):Beta1State{
 const strings=(v:unknown):v is string[]=>Array.isArray(v)&&v.every(isText)
 if(!hasFields(value,['schema','scope','operation_id','domain','items','coverage','missing_inputs'])||value.schema!=='d12.beta1-owner-state.v1'||value.scope!==scope||value.operation_id!==id||value.domain!==domain||!['complete','partial','unavailable'].includes(String(value.coverage))||!strings(value.missing_inputs)||!Array.isArray(value.items)||value.items.length>16)throw new Error('当前状态响应不匹配，未显示旧状态。')
 for(const item of value.items)if(!hasFields(item,['ref','type_name','revision','state','source_refs','related_refs','reason_codes'],['managed_nodes'])||!isText(item.ref)||!isText(item.type_name)||!isText(item.state)||!isInteger(item.revision,1)||!strings(item.source_refs)||!strings(item.related_refs)||!strings(item.reason_codes))throw new Error('当前状态条目不匹配，未显示旧状态。')
 for(const item of value.items)if(item.managed_nodes!==undefined&&(item.type_name!=='d08.joint_window.v1'||!Array.isArray(item.managed_nodes)||item.managed_nodes.length>8||item.managed_nodes.some((node:unknown)=>!hasFields(node,['node_id','executor_kind'])||!isText(node.node_id)||!['source_note','draft_file','contact'].includes(String(node.executor_kind)))))throw new Error('当前窗口节点响应不匹配。')
 return{scope,operationId:id,domain,items:value.items as Beta1State['items'],coverage:value.coverage as Beta1State['coverage'],missing_inputs:value.missing_inputs}
}

export interface JointCommandSelectionInput{long_plan_ref:string;joint_plan_ref:string;node_id:string;executor_kind:'draft_file'|'contact';input_original_ref:string;role_ref:string|null}
export interface FrozenJointCommandReceipt{operationId:string;actualOperationId:string;commandOriginalRef:string;commandOriginalDigest:string;nodeId:string;executorKind:'draft_file'|'contact';typedInputOriginalRef:string;typedInputOriginalDigest:string;typedRequestDigest:string;originalDigest:string}
export interface PreparedJointCommand{schema:'d12.prepared-joint-command.v1';selection:JointCommandSelectionInput;request:Record<string,unknown>;digest:string}
export const pendingFrozenJointCommands=new Map<string,{input:JointCommandSelectionInput;operationId:string;prepared?:PreparedJointCommand}>()
