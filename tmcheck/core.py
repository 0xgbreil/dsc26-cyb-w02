"""tmcheck core: load, validate and analyse a STRIDE threat model."""
from __future__ import annotations

import re
from dataclasses import dataclass

import yaml

STRIDE = ("S", "T", "R", "I", "D", "E")
KINDS = ("external_entity", "process", "data_store")
STATUSES = ("open", "mitigated", "accepted")
SECTIONS = ("zones", "elements", "flows", "threats")
ENCRYPTED = ("https", "tls", "mtls", "sftp", "ssh")


class ModelError(Exception):
    """The file cannot be read as a threat model."""


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
    level: str        # "high" | "medium" | "low"



# Small helpers --------------------------------------------------------------------------


def _items(model: dict, section: str) -> list[dict]:
    """The mapping entries of one section. Missing, null or non-list sections give []."""
    value = model.get(section) if isinstance(model, dict) else None
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _by_id(model: dict, section: str) -> dict:
    """id -> entry for one section. The first entry wins when an id is repeated."""
    table: dict = {}
    for item in _items(model, section):
        ident = item.get("id")
        if ident is None:
            continue
        try:
            table.setdefault(ident, item)
        except TypeError:  # unhashable id, for example a list
            pass
    return table


def _get(table: dict, key):
    """table.get(key) that returns None instead of raising on an unhashable key."""
    try:
        return table.get(key)
    except TypeError:
        return None


def _is_score(value) -> bool:
    """An integer from 1 to 5. bool is a subclass of int and 4.0 is a float: neither counts."""
    return type(value) is int and 1 <= value <= 5


def _is_blank(text) -> bool:
    """True when there is no text, or only whitespace."""
    return text is None or not str(text).strip()


def _natural_key(text) -> list:
    """Sort key where 'T2' comes before 'T10'. Parts alternate text, number, text, ..."""
    parts = re.split(r"(\d+)", str(text))
    return [int(part) if i % 2 else part for i, part in enumerate(parts)]


def _element_categories(element: dict) -> set[str] | None:
    """STRIDE letters for an element, or None when its kind is not valid."""
    kind = element.get("kind")
    if isinstance(kind, str) and kind in KINDS:
        return applicable(kind, is_log=element.get("is_log") is True)
    return None


# --------------------------------------------------------------------------
# load_model
# --------------------------------------------------------------------------

def load_model(path) -> dict:
    """Read the YAML file with yaml.safe_load and return the mapping.

    Missing or null `zones`, `elements`, `flows`, `threats` become []. Raise ModelError if the
    file cannot be read, is not valid YAML, uses a tag safe_load refuses, has a top level that
    is not a mapping, or has one of the four sections that is not a list.
    """
    try:
        # Bytes: PyYAML detects the encoding itself. safe_load only: the file chooses
        # nothing about which Python objects get built.
        with open(path, "rb") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError, ValueError, RecursionError) as exc:
        # YAMLError covers bad syntax, bad encoding and refused tags (ConstructorError);
        # ValueError covers impossible dates such as 2024-13-45.
        raise ModelError(f"cannot load {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ModelError("the top level of the model must be a mapping")

    for section in SECTIONS:
        value = data.get(section)
        if value is None:
            data[section] = []
        elif not isinstance(value, list):
            raise ModelError(f"section '{section}' must be a list")
    return data


# --------------------------------------------------------------------------
# applicable
# --------------------------------------------------------------------------

def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    """STRIDE per element: the categories that apply to `kind`. Unknown kind: ValueError."""
    if kind == "external_entity":
        return {"S", "R"}
    if kind == "process":
        return set(STRIDE)
    if kind == "data_store":
        # No S: a database does not log in to anything. R only where the evidence lives.
        return {"T", "I", "D", "R"} if is_log else {"T", "I", "D"}
    if kind == "data_flow":
        return {"T", "I", "D"}
    raise ValueError(f"unknown kind: {kind!r}")


# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------

def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    issues: set[Issue] = set()
    zones = _by_id(model, "zones")
    elements = _by_id(model, "elements")
    flows = _by_id(model, "flows")

    # DUPLICATE_ID: zones, elements, flows and threats share one id space.
    counts: dict = {}
    for section in SECTIONS:
        for item in _items(model, section):
            ident = item.get("id")
            if ident is None:
                continue
            try:
                counts[ident] = counts.get(ident, 0) + 1
            except TypeError:
                pass
    for ident, count in counts.items():
        if count > 1:
            issues.add(Issue(str(ident), "DUPLICATE_ID", f"id is used {count} times"))

    # Elements: BAD_KIND, UNKNOWN_ZONE
    for element in _items(model, "elements"):
        ref = str(element.get("id"))
        if _element_categories(element) is None:
            issues.add(Issue(ref, "BAD_KIND", f"kind {element.get('kind')!r} is not valid"))
        if _get(zones, element.get("zone")) is None:
            issues.add(Issue(ref, "UNKNOWN_ZONE", f"zone {element.get('zone')!r} is not defined"))

    # Flows: UNKNOWN_REF, INVALID_FLOW
    for flow in _items(model, "flows"):
        ref = str(flow.get("id"))
        source, target = flow.get("source"), flow.get("target")
        source_el, target_el = _get(elements, source), _get(elements, target)

        if source_el is None or target_el is None:
            issues.add(Issue(ref, "UNKNOWN_REF", "source or target is not an element"))

        invalid = source == target
        if not invalid and source_el is not None and target_el is not None:
            # Spec gap: "neither end is a process" is judged only when both ends exist.
            # A missing end is already reported as UNKNOWN_REF.
            invalid = (source_el.get("kind") != "process"
                       and target_el.get("kind") != "process")
        if invalid:
            issues.add(Issue(ref, "INVALID_FLOW",
                             "source equals target, or neither end is a process"))

    # Threats: UNKNOWN_REF, category, score and decision codes
    for threat in _items(model, "threats"):
        ref = str(threat.get("id"))
        target = threat.get("target")
        category = threat.get("category")
        target_el = _get(elements, target)
        target_is_flow = _get(flows, target) is not None

        if target_el is None and not target_is_flow:
            issues.add(Issue(ref, "UNKNOWN_REF", f"target {target!r} is not an element or a flow"))

        if not (isinstance(category, str) and category in STRIDE):
            issues.add(Issue(ref, "BAD_CATEGORY", f"category {category!r} is not one of S T R I D E"))
        else:
            if target_el is not None:
                allowed = _element_categories(target_el)  # None when the kind is bad
            elif target_is_flow:
                allowed = applicable("data_flow")
            else:
                allowed = None
            if allowed is not None and category not in allowed:
                issues.add(Issue(ref, "INAPPLICABLE_CATEGORY",
                                 f"{category} does not apply to {target}"))

        bad_scores = [name for name in ("likelihood", "impact") if not _is_score(threat.get(name))]
        if bad_scores:
            issues.add(Issue(ref, "BAD_SCORE", "not an integer from 1 to 5: " + ", ".join(bad_scores)))

        status = threat.get("status")
        if not (isinstance(status, str) and status in STATUSES):
            issues.add(Issue(ref, "BAD_STATUS", f"status {status!r} is not open, mitigated or accepted"))
        elif status == "mitigated" and _is_blank(threat.get("mitigation")):
            issues.add(Issue(ref, "MISSING_MITIGATION", "mitigated but no mitigation text"))
        elif status == "accepted" and _is_blank(threat.get("justification")):
            issues.add(Issue(ref, "MISSING_JUSTIFICATION", "accepted but no justification text"))

    return sorted(issues)


# --------------------------------------------------------------------------
# crossing_flows, coverage_gaps
# --------------------------------------------------------------------------

def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    elements = _by_id(model, "elements")
    result = []
    for flow in _items(model, "flows"):
        source = _get(elements, flow.get("source"))
        target = _get(elements, flow.get("target"))
        if source is None or target is None:
            continue  # a flow with an unknown end is skipped
        if source.get("zone") != target.get("zone"):
            result.append(flow.get("id"))
    return result


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    elements = _by_id(model, "elements")
    crossing = crossing_flows(model)

    # Scope: every crossing flow plus both of its end elements, with the letters
    # that apply to each of them.
    scope: dict = {}
    for flow in _items(model, "flows"):
        if flow.get("id") not in crossing:
            continue
        scope.setdefault(flow.get("id"), set()).update(applicable("data_flow"))
        for end in (flow.get("source"), flow.get("target")):
            element = _get(elements, end)
            letters = _element_categories(element) if element is not None else None
            if letters is not None:
                scope.setdefault(end, set()).update(letters)

    # Any threat with that target and category covers the pair, in any status.
    covered = set()
    for threat in _items(model, "threats"):
        try:
            covered.add((threat.get("target"), threat.get("category")))
        except TypeError:
            pass

    gaps = [Gap(str(ref), letter)
            for ref, letters in scope.items()
            for letter in STRIDE
            if letter in letters and (ref, letter) not in covered]
    return sorted(gaps, key=lambda gap: (gap.ref, STRIDE.index(gap.category)))


# --------------------------------------------------------------------------
# policy_findings
# --------------------------------------------------------------------------

def policy_findings(model: dict) -> list[Issue]:
    """UNENCRYPTED_CROSSING, UNAUTHENTICATED_INBOUND, PII_STORE_WITHOUT_I_THREAT, sorted by (ref, code)."""
    elements = _by_id(model, "elements")
    zones = _by_id(model, "zones")
    crossing = crossing_flows(model)
    findings: set[Issue] = set()

    for flow in _items(model, "flows"):
        if flow.get("id") not in crossing:
            continue
        ref = str(flow.get("id"))

        protocol = flow.get("protocol")
        if not (isinstance(protocol, str) and protocol.lower() in ENCRYPTED):
            findings.add(Issue(ref, "UNENCRYPTED_CROSSING",
                               f"protocol {protocol!r} is not https, tls, mtls, sftp or ssh"))

        # Crossing flows always have both end elements.
        source_zone = _get(zones, _get(elements, flow.get("source")).get("zone"))
        target_zone = _get(zones, _get(elements, flow.get("target")).get("zone"))
        if source_zone is not None and target_zone is not None:
            source_trust, target_trust = source_zone.get("trust"), target_zone.get("trust")
            if (type(source_trust) is int and type(target_trust) is int
                    and target_trust > source_trust
                    and flow.get("authenticated") is not True):
                findings.add(Issue(ref, "UNAUTHENTICATED_INBOUND",
                                   "flow into a more trusted zone is not authenticated"))

    has_i_threat = set()
    for threat in _items(model, "threats"):
        if threat.get("category") == "I":
            try:
                has_i_threat.add(threat.get("target"))
            except TypeError:
                pass
    for element in _items(model, "elements"):
        if (element.get("kind") == "data_store" and element.get("holds_pii") is True
                and element.get("id") not in has_i_threat):
            findings.add(Issue(str(element.get("id")), "PII_STORE_WITHOUT_I_THREAT",
                               "store holds personal data but has no information-disclosure threat"))

    return sorted(findings, key=lambda issue: (issue.ref, issue.code, issue.message))


# --------------------------------------------------------------------------
# rank
# --------------------------------------------------------------------------

def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    rows = []
    for threat in _items(model, "threats"):
        if threat.get("status") != "open":
            continue
        likelihood, impact = threat.get("likelihood"), threat.get("impact")
        if not (_is_score(likelihood) and _is_score(impact)):
            continue  # an invalid score is skipped, not ranked
        score = likelihood * impact
        level = "high" if score >= 15 else "medium" if score >= 8 else "low"
        rows.append((score, impact, threat.get("id"), level))

    rows.sort(key=lambda row: (-row[0], -row[1], _natural_key(row[2])))
    return [RankedThreat(id=row[2], score=row[0], level=row[3]) for row in rows]
