import pytest

from verisoc.evaluation.triage import paired_recall_interval, risk_curve, triage_metrics


def rows():
    return [
        dict(
            scenario_id=str(i),
            family=family,
            gold_verdict=gold,
            priority=priority,
            flagged=priority > 0,
            other=False,
        )
        for i, (family, gold, priority) in enumerate(
            [
                ("auth", "malicious", 2),
                ("auth", "benign", 2),
                ("process", "malicious", 1),
                ("flow", "benign", 0),
                ("flow", "needs_review", 1),
            ]
        )
    ]


def test_false_positives_and_ambiguous_are_not_silently_removed():
    result = triage_metrics(rows())
    assert result["recall"] == 1 and result["benign_fpr"] == 0.5
    assert result["precision_on_decidable"] == 2 / 3
    assert result["precision_ambiguous_as_negative"] == 0.5
    assert result["ambiguous_flagged"] == 1
    assert result["family_macro_recall"] == 1


def test_empty_emission_precision_is_undefined_and_no_policy_is_promoted():
    curve = risk_curve(rows())
    assert curve["selected_threshold"] is None
    assert curve["curve"][-1]["precision_on_decidable"] is None
    assert curve["calibration_status"] == "no_nonempty_feasible_policy"
    assert triage_metrics([])["recall"] is None


def test_bootstrap_uses_families_and_retains_pairing():
    result = paired_recall_interval(rows(), "flagged", "other", replicates=100)
    assert result["families"] == 3 and result["difference"] == 1
    assert result == paired_recall_interval(rows(), "flagged", "other", replicates=100)
    with pytest.raises(ValueError):
        paired_recall_interval(rows() + rows(), "flagged", "other")
