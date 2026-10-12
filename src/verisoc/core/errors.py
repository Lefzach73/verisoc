"""Stable public errors; messages never contain foreign record details."""


class VeriSOCError(Exception):
    code = "invalid_request"


class NotFound(VeriSOCError):
    code = "not_found"


class Conflict(VeriSOCError):
    code = "conflicting_import"


class BudgetExceeded(VeriSOCError):
    code = "budget_exceeded"


class ProviderFailure(VeriSOCError):
    code = "provider_failed"


class Unauthorized(VeriSOCError):
    code = "unauthorized"


class RateLimited(VeriSOCError):
    code = "rate_limited"
