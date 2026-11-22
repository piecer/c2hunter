"""Real retry detector -> calculate/asdict -> public projection witness; no network."""
import json
import runpy
import sys
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "analysis/src"), str(ROOT / "controller/src")]

from c2hunter_analysis.tcp_sessions import MAX_SYN_RETRY_RESPONSE_ROWS
from c2hunter_controller.app import _public_candidate
from c2hunter_controller.jobs import calculate
from fastapi.encoders import jsonable_encoder

producer = runpy.run_path(str(ROOT / "analysis/tests/test_tcp_connection_attempts.py"))
job = runpy.run_path(str(ROOT / "controller/tests/test_tcp_connection_attempt_candidates.py"))["retry_job"]()
job["id"] = "queue-warning-job"
records = []
for index in range(5):
    retry = deepcopy(job["flow_records"][0])
    retry["source_port"] += index
    records.append(retry)
    if index < 3:
        records.append(asdict(replace(producer["inbound_response"](rst=1), destination_port=50000 + index)))
    if index == 4:
        records.extend(asdict(replace(producer["inbound_response"](syn_ack=1), destination_port=50004,
                                     timestamp=producer["START"] + timedelta(seconds=12.1, microseconds=n)))
                       for n in range(MAX_SYN_RETRY_RESPONSE_ROWS + 1))
job["flow_records"] = records
candidates = calculate(job)
assert len(candidates) == 1
candidate = candidates[0]
# Only the random resource handle is stabilized; evidence order/values are unmodified.
candidate["id"] = "queue-warning-candidate"
public = jsonable_encoder(_public_candidate(candidate, job))
evidence = public["evidence"]
assert all(not item["warnings"] for item in evidence[:3]), evidence[:3]
assert any("no_response_is_not_host_unavailable" in item["warnings"] for item in evidence[3:])
assert any("response_correlation_truncated" in item["warnings"] for item in evidence[3:])
origins = {name: module.__file__ for name, module in sys.modules.copy().items()
           if name.startswith("c2hunter_") and getattr(module, "__file__", None)}
assert origins and all(Path(path).is_relative_to(ROOT) for path in origins.values())
print(json.dumps({"candidate": public, "origins": origins}, sort_keys=True))
