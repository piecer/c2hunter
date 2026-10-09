from __future__ import annotations

from copy import deepcopy
from typing import Any

SELECTION_VERSION = "behavior-selection-v1"
MAX_SELECTION_CANDIDATES = 2048
MAX_DISCOVERY_INPUT_FLOWS = 100_000


def select_shadow_candidates(
    legacy: list[dict[str, Any]],
    behavior: list[dict[str, Any]],
    *,
    limit: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Reserve bounded review capacity without rewriting deterministic scores."""
    if not 1 <= limit <= 5:
        raise ValueError("candidate_limit must be between 1 and 5")
    if len(legacy) + len(behavior) > MAX_SELECTION_CANDIDATES:
        raise ValueError("behavior discovery candidate pool exceeds its admission limit")
    pool: dict[str, dict[str, Any]] = {}
    for candidate in legacy:
        item = deepcopy(candidate)
        item["discovery_origin"] = "PREFILTER" if item.get("source") == "AI_PREFILTER" else "RULE"
        pool[str(item["candidate_ip"])] = item
    for candidate in behavior:
        peer = str(candidate["candidate_ip"])
        existing_item = pool.get(peer)
        if existing_item is None:
            item = deepcopy(candidate)
            item["discovery_origin"] = "BEHAVIOR"
            pool[peer] = item
        elif existing_item.get("candidate_kind") != "COMMUNICATION_STATUS":
            item = existing_item
            item["behavior_anomaly_score"] = candidate["behavior_anomaly_score"]
            item["discovery_origin"] = (
                "RULE_AND_BEHAVIOR" if item["discovery_origin"] == "RULE" else "BEHAVIOR"
            )
            item["evidence"] = [*candidate.get("evidence", []), *item.get("evidence", [])][:50]
        # Transport-only operational candidates must not be relabeled as C2 evidence.
    ranked = sorted(
        pool.values(),
        key=lambda item: (
            -(0.55 * float(item.get("score", 0)) + 0.25 * float(item.get("prefilter_score", 0))),
            str(item["candidate_ip"]),
        ),
    )
    discovery = sorted(
        (item for item in ranked if item["discovery_origin"] == "BEHAVIOR"),
        key=lambda item: (-float(item["behavior_anomaly_score"]), str(item["candidate_ip"])),
    )
    reserved = discovery[: min(2, limit)]
    reserved_ips = {item["candidate_ip"] for item in reserved}
    ordered = reserved + [item for item in ranked if item["candidate_ip"] not in reserved_ips]
    selected = ordered[:limit]
    selected_ips = {item["candidate_ip"] for item in selected}
    inventory = [
        {
            "candidate_id": item["id"],
            "external_ip": item["candidate_ip"],
            "origin": item["discovery_origin"],
            "existing_score": item.get("score", 0),
            "anomaly_score": item.get("behavior_anomaly_score"),
            "selected": item["candidate_ip"] in selected_ips,
            "reason": (
                "DISCOVERY_RESERVED"
                if item["candidate_ip"] in reserved_ips
                else "RANKED"
                if item["candidate_ip"] in selected_ips
                else "BUDGET_LIMIT"
            ),
        }
        for item in ordered
    ]
    summary = {
        "version": SELECTION_VERSION,
        "candidate_pool_count": len(pool),
        "selected_count": len(selected),
        "omitted_count": len(pool) - len(selected),
        "discovery_candidate_count": sum(
            item["discovery_origin"] in {"BEHAVIOR", "RULE_AND_BEHAVIOR"} for item in ranked
        ),
        "discovery_selected_count": sum(
            item["discovery_origin"] in {"BEHAVIOR", "RULE_AND_BEHAVIOR"} for item in selected
        ),
        "rule_free_selected_count": sum(
            item["discovery_origin"] == "BEHAVIOR" for item in selected
        ),
        "reserved_discovery_slots": len(reserved),
        "warnings": ["NO_HISTORICAL_BASELINE", "SHADOW_ONLY_NOT_CALIBRATED"],
    }
    return selected, inventory, summary
