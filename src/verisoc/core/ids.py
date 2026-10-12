from uuid import NAMESPACE_URL, UUID, uuid5


def stable_id(*parts: object) -> UUID:
    return uuid5(NAMESPACE_URL, "verisoc:" + ":".join(str(p) for p in parts))


def demo_tenant(name: str) -> UUID:
    if name not in ("demo-a", "demo-b", "eval-mfg", "eval-health", "eval-retail", "eval-services"):
        raise ValueError("Only explicit synthetic demo tenants are supported")
    return stable_id("tenant", name)
