import math

import pytest

from verisoc.evaluation.v05_statistics import fpr_upper


def test_zero_false_alarms_on_sixteen_does_not_establish_five_percent():
    assert fpr_upper(0, 16) == pytest.approx(1 - 0.05 ** (1 / 16))
    assert 0.17 < fpr_upper(0, 16) < 0.18
    assert fpr_upper(0, 58) > 0.05
    assert fpr_upper(0, 59) < 0.05
    assert fpr_upper(0, 0) is None
    assert fpr_upper(16, 16) == 1


def test_exact_upper_satisfies_binomial_tail_equation():
    p = fpr_upper(4, 16)
    assert p > 0.25
    assert sum(math.comb(16, k) * p**k * (1 - p) ** (16 - k) for k in range(5)) == pytest.approx(
        0.05
    )
    with pytest.raises(ValueError):
        fpr_upper(17, 16)
