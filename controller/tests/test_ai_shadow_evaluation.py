from __future__ import annotations


def test_evaluation_uses_production_budget_and_does_not_call_unselected_candidates() -> None:
    from c2hunter_controller.ai_analysis import FakeGateway
    from c2hunter_controller.ai_evaluation_pipeline import evaluate_shadow_job

    candidates = [
        {
            "id": f"candidate-{index}",
            "candidate_ip": f"198.51.100.{index}",
            "score": 90 - index,
            "evidence": [{"type": "OBSERVATION", "description": "test"}],
        }
        for index in range(1, 7)
    ]
    report = evaluate_shadow_job(
        {"id": "job", "status": "COMPLETED"},
        candidates,
        labels={"198.51.100.1": False, "198.51.100.6": True},
        candidate_limit=1,
        gateway=FakeGateway(),
        data_provenance="synthetic",
    )
    assert report["candidate_limit"] == 1
    assert report["model_calls"] == 1
    assert report["data_provenance"] == "synthetic"
    assert report["model_provider"] == "fake"
    assert report["candidate_generation"]["recall_before_selection"] == 1.0
    assert report["candidate_generation"]["recall_at_budget"] == 0.0
    assert report["verdict"]["end_to_end_recall"] == 0.0
    assert report["verdict"]["false_positive"] == 1
    assert report["semantic_accuracy_verified"] is False
