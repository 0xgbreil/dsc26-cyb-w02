"""tmcheck core: load, validate and analyse a STRIDE threat model."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml


class ModelError(Exception):
    """The model file cannot be used at all."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str
    category: str


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str


SECTIONS = ("zones", "elements", "flows", "threats")
STRIDE = ("S", "T", "R", "I", "D", "E")  # canonical order, NOT alphabetical
KINDS = ("external_entity", "process", "data_store")
STATUSES = ("open", "mitigated", "accepted")
ENCRYPTED = {"https", "tls", "mtls", "sftp", "ssh"}


# ---------------------------------------------------------------- helpers
def _items(model: dict, key: str) -> list[dict]:
    """Section as a list of mappings; tolerant of missing/None/odd entries."""
    value = model.get(key) if isinstance(model, dict) else None
    if not isinstance(value, list):
        return []
    return [x for x in value if isinstance(x, dict)]


def _is_score(v: Any) -> bool:
    # bool is a subclass of int, so isinstance() is not enough; 4.0 is a float.
    return type(v) is int and 1 <= v <= 5


def _has_text(v: Any) -> bool:
    return isinstance(v, str) and v.strip() != ""


def _natural_key(s: Any) -> list:
    parts = re.split(r"(\d+)", str(s))
    return [(0, int(p)) if p.isdigit() else (1, p) for p in parts if p != ""]


def _stride_pos(c: str) -> int:
    return STRIDE.index(c)


def _element_map(model: dict) -> dict:
    out: dict = {}
    for e in _items(model, "elements"):
        eid = e.get("id")
        if isinstance(eid, (str, int)) and not isinstance(eid, bool):
            out.setdefault(eid, e)
    return out


def _flow_map(model: dict) -> dict:
    out: dict = {}
    for f in _items(model, "flows"):
        fid = f.get("id")
        if isinstance(fid, (str, int)) and not isinstance(fid, bool):
            out.setdefault(fid, f)
    return out


def _hashable(v: Any) -> bool:
    try:
        hash(v)
    except TypeError:
        return False
    return True


# ------------------------------------------------------------------ load
def load_model(path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, UnicodeDecodeError) as exc:
        raise ModelError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:  # includes ConstructorError (unsafe tags)
        raise ModelError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ModelError("top level of the model must be a mapping")
    for key in SECTIONS:
        value = data.get(key)
        if value is None:
            data[key] = []
        elif not isinstance(value, list):
            raise ModelError(f"section '{key}' must be a list")
    return data


# ------------------------------------------------------------ applicable
def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    if kind == "external_entity":
        return {"S", "R"}
    if kind == "process":
        return set(STRIDE)
    if kind == "data_store":
        return {"T", "I", "D", "R"} if is_log else {"T", "I", "D"}
    if kind == "data_flow":
        return {"T", "I", "D"}
    raise ValueError(f"unknown kind: {kind!r}")


# -------------------------------------------------------------- validate
def validate(model: dict) -> list[Issue]:
    issues: set[Issue] = set()
    zones = _items(model, "zones")
    elements = _items(model, "elements")
    flows = _items(model, "flows")
    threats = _items(model, "threats")

    # one id space for the whole model
    seen: dict = {}
    for item in zones + elements + flows + threats:
        i = item.get("id")
        if i is None or not _hashable(i):
            continue
        seen[i] = seen.get(i, 0) + 1
    for i, n in seen.items():
        if n > 1:
            issues.add(Issue(str(i), "DUPLICATE_ID", f"id used {n} times"))

    zone_ids = {z.get("id") for z in zones if _hashable(z.get("id"))}
    emap = _element_map(model)
    fmap = _flow_map(model)

    for e in elements:
        ref = str(e.get("id"))
        if e.get("kind") not in KINDS:
            issues.add(Issue(ref, "BAD_KIND", f"bad kind {e.get('kind')!r}"))
        z = e.get("zone")
        if not _hashable(z) or z not in zone_ids:
            issues.add(Issue(ref, "UNKNOWN_ZONE", f"unknown zone {z!r}"))

    for f in flows:
        ref = str(f.get("id"))
        src, dst = f.get("source"), f.get("target")
        src_ok = _hashable(src) and src in emap
        dst_ok = _hashable(dst) and dst in emap
        if not src_ok:
            issues.add(Issue(ref, "UNKNOWN_REF", f"unknown source {src!r}"))
        if not dst_ok:
            issues.add(Issue(ref, "UNKNOWN_REF", f"unknown target {dst!r}"))
        if src_ok and dst_ok:
            if src == dst:
                issues.add(Issue(ref, "INVALID_FLOW", "source equals target"))
            elif emap[src].get("kind") != "process" and emap[dst].get("kind") != "process":
                issues.add(Issue(ref, "INVALID_FLOW", "neither end is a process"))

    for t in threats:
        ref = str(t.get("id"))
        target = t.get("target")
        known = _hashable(target) and (target in emap or target in fmap)
        if not known:
            issues.add(Issue(ref, "UNKNOWN_REF", f"unknown target {target!r}"))

        cat = t.get("category")
        if not (isinstance(cat, str) and cat in STRIDE):
            issues.add(Issue(ref, "BAD_CATEGORY", f"bad category {cat!r}"))
        elif known:
            if target in emap:
                el = emap[target]
                kind = el.get("kind")
                if kind in KINDS:
                    ok = applicable(kind, is_log=el.get("is_log") is True)
                else:
                    ok = None  # BAD_KIND is reported on the element itself
            else:
                ok = applicable("data_flow")
            if ok is not None and cat not in ok:
                issues.add(Issue(ref, "INAPPLICABLE_CATEGORY",
                                 f"{cat} does not apply to {target}"))

        for field in ("likelihood", "impact"):
            if not _is_score(t.get(field)):
                issues.add(Issue(ref, "BAD_SCORE", f"{field} must be an int 1-5"))

        status = t.get("status")
        if status not in STATUSES:
            issues.add(Issue(ref, "BAD_STATUS", f"bad status {status!r}"))
        elif status == "mitigated" and not _has_text(t.get("mitigation")):
            issues.add(Issue(ref, "MISSING_MITIGATION", "mitigation text is empty"))
        elif status == "accepted" and not _has_text(t.get("justification")):
            issues.add(Issue(ref, "MISSING_JUSTIFICATION", "justification text is empty"))

    return sorted(issues, key=lambda i: (i.ref, i.code, i.message))


# ------------------------------------------------------------- crossings
def _crossing(model: dict) -> list[dict]:
    emap = _element_map(model)
    out = []
    for f in _items(model, "flows"):
        s, d = f.get("source"), f.get("target")
        if not (_hashable(s) and _hashable(d) and s in emap and d in emap):
            continue
        if emap[s].get("zone") != emap[d].get("zone"):
            out.append(f)
    return out


def crossing_flows(model: dict) -> list[str]:
    return [f.get("id") for f in _crossing(model)]


# -------------------------------------------------------------- coverage
def coverage_gaps(model: dict) -> list[Gap]:
    emap = _element_map(model)
    covered = set()
    for t in _items(model, "threats"):
        if _hashable(t.get("target")) and _hashable(t.get("category")):
            covered.add((t.get("target"), t.get("category")))

    scope: dict = {}  # ref -> set of applicable categories
    for f in _crossing(model):
        scope[f.get("id")] = applicable("data_flow")
        for end in (f.get("source"), f.get("target")):
            el = emap[end]
            kind = el.get("kind")
            if kind in KINDS:
                scope[end] = applicable(kind, is_log=el.get("is_log") is True)

    gaps = [Gap(str(ref), c)
            for ref, cats in scope.items()
            for c in cats
            if (ref, c) not in covered]
    return sorted(gaps, key=lambda g: (g.ref, _stride_pos(g.category)))


# ---------------------------------------------------------------- policy
def policy_findings(model: dict) -> list[Issue]:
    found: list[Issue] = []
    emap = _element_map(model)
    trust = {z.get("id"): z.get("trust") for z in _items(model, "zones")
             if _hashable(z.get("id"))}

    for f in _crossing(model):
        ref = str(f.get("id"))
        proto = f.get("protocol")
        if not (isinstance(proto, str) and proto.casefold() in ENCRYPTED):
            found.append(Issue(ref, "UNENCRYPTED_CROSSING", f"protocol {proto!r}"))
        zs = emap[f.get("source")].get("zone")
        zd = emap[f.get("target")].get("zone")
        ts, td = trust.get(zs), trust.get(zd)
        if (type(ts) is int and type(td) is int and td > ts
                and f.get("authenticated") is not True):
            found.append(Issue(ref, "UNAUTHENTICATED_INBOUND",
                               "inbound to a more trusted zone without authentication"))

    has_i = {t.get("target") for t in _items(model, "threats")
             if t.get("category") == "I" and _hashable(t.get("target"))}
    for e in _items(model, "elements"):
        if (e.get("kind") == "data_store" and e.get("holds_pii") is True
                and e.get("id") not in has_i):
            found.append(Issue(str(e.get("id")), "PII_STORE_WITHOUT_I_THREAT",
                               "store holds PII but has no I threat"))

    return sorted(found, key=lambda i: (i.ref, i.code, i.message))


# ------------------------------------------------------------------ rank
def rank(model: dict) -> list[RankedThreat]:
    rows = []
    for t in _items(model, "threats"):
        if t.get("status") != "open":
            continue
        l, i = t.get("likelihood"), t.get("impact")
        if not (_is_score(l) and _is_score(i)):
            continue
        score = l * i
        level = "high" if score >= 15 else "medium" if score >= 8 else "low"
        rows.append((score, i, t.get("id"), level))
    rows.sort(key=lambda r: (-r[0], -r[1], _natural_key(r[2])))
    return [RankedThreat(str(tid), score, level) for score, _, tid, level in rows]
