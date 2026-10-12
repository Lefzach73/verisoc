"""Binomial bounds are descriptive only unless trials are independent Bernoulli samples."""

import math


def fpr_upper(false_positives: int, benign_cases: int, alpha: float = 0.05) -> float | None:
    if (
        type(false_positives) is not int
        or type(benign_cases) is not int
        or not 0 <= false_positives <= benign_cases <= 500
        or not 0 < alpha < 1
    ):
        raise ValueError("Invalid binomial counts or confidence level")
    if not benign_cases:
        return None
    if false_positives == benign_cases:
        return 1.0
    if false_positives == 0:
        return float(1 - alpha ** (1 / benign_cases))
    low, high = 0.0, 1.0
    for _ in range(80):
        p = (low + high) / 2
        cdf = math.fsum(
            math.comb(benign_cases, k) * p**k * (1 - p) ** (benign_cases - k)
            for k in range(false_positives + 1)
        )
        if cdf > alpha:
            low = p
        else:
            high = p
    return (low + high) / 2
