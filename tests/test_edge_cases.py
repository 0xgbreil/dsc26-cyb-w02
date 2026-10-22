"""My own tests: one per rule in the spec."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tmcheck.__main__ import main
from tmcheck.core import (
    Gap, Issue, ModelError, RankedThreat, applicable, coverage_gaps, crossing_flows,
    load_model, policy_findings, rank, validate,
)

ROOT = Path(__file__).resolve().parent.parent
MODEL = ROOT / "models" / "rawaj_scoring.yaml"


def base():
    """A clean model. f1 crosses (trust 1 -> 3); db holds PII; log is a log store."""
    return {
        "zones": [{"id": "z1", "trust": 1}, {"id": "z2", "trust": 3}],
        "elements": [
            {"id": "user", "kind": "external_entity", "zone": "z1"},
            {"id": "api", "kind": "process", "zone": "z2"},
            {"id": "db", "kind": "data_store", "zone": "z2", "holds_pii": True},
            {"id": "log", "kind": "data_store", "zone": "z2", "is_log": True},
        ],
        "flows": [
            {"id": "f1", "source": "user", "target": "api", "protocol": "https", "authenticated": True},
            {"id": "f2", "source": "api", "target": "db", "protocol": "tls", "authenticated": True},
        ],
        "threats": [],
    }


def threat(tid, target="api", category="T", likelihood=3, impact=3, status="open", **extra):
    return {"id": tid, "target": target, "category": category, "title": "a threat title",
            "likelihood": likelihood, "impact": impact, "status": status, **extra}


def pairs(issues):
    return {(i.ref, i.code) for i in issues}


def codes_for(threats):
    m = base()
    m["threats"] = threats
    return {i.code for i in validate(m)}


# ---------------------------------------------------------------- H01 load_model

@pytest.mark.parametrize("text", [
    "zones: !!python/object/apply:os.system ['echo pwned']\n",   # tag safe_load refuses
    "- a\n- b\n",                                                # list at the top level
    "zones: [unclosed\n",                                        # invalid YAML
    "zones: {a: 1}\n",                                           # section is a mapping
    "elements: just text\n",                                     # section is a string
    "",                                                          # empty file: top level is None
    "when: 2024-13-45\n",                                        # impossible date: ValueError
])
def test_load_refuses_bad_files(tmp_path, text):
    p = tmp_path / "m.yaml"
    p.write_text(text)
    with pytest.raises(ModelError):
        load_model(p)


def test_load_missing_file_and_directory(tmp_path):
    with pytest.raises(ModelError):
        load_model(tmp_path / "nope.yaml")
    with pytest.raises(ModelError):
        load_model(tmp_path)


def test_load_invalid_utf8(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_bytes(b"zones: \xff\xfe\x00bad\n")
    with pytest.raises(ModelError):
        load_model(p)


def test_load_missing_and_null_sections_become_empty_lists(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text("zones:\n  - {id: z, trust: 1}\nflows:\n")
    m = load_model(p)
    assert m["zones"] == [{"id": "z", "trust": 1}]
    assert m["elements"] == [] and m["flows"] == [] and m["threats"] == []


def test_load_accepts_str_and_path(tmp_path):
    p = tmp_path / "m.yaml"
    p.write_text("zones: []\n")
    assert load_model(p) == load_model(str(p))


# ---------------------------------------------------------------- applicable

def test_applicable_full_table_and_return_type():
    assert applicable("external_entity") == {"S", "R"}
    assert applicable("process") == {"S", "T", "R", "I", "D", "E"}
    assert applicable("data_store") == {"T", "I", "D"}
    assert applicable("data_store", is_log=True) == {"T", "I", "D", "R"}
    assert applicable("data_flow") == {"T", "I", "D"}
    assert isinstance(applicable("process"), set)


def test_applicable_is_log_does_not_change_other_kinds():
    assert applicable("external_entity", is_log=True) == {"S", "R"}
    assert applicable("data_flow", is_log=True) == {"T", "I", "D"}


@pytest.mark.parametrize("kind", ["robot", "", "Process", "flow", None])
def test_applicable_unknown_kind(kind):
    with pytest.raises(ValueError):
        applicable(kind)


def test_applicable_is_log_is_keyword_only():
    with pytest.raises(TypeError):
        applicable("data_store", True)


# ---------------------------------------------------------------- validate

def test_clean_model_has_no_issues():
    assert validate(base()) == []


def test_validate_tolerates_missing_sections():
    assert validate({}) == []
    assert validate({"zones": None, "threats": None}) == []


def test_duplicate_id_one_space_for_everything():
    m = base()
    m["flows"][0]["id"] = "api"            # a flow reusing an element id
    m["threats"] = [threat("db")]          # a threat reusing a store id
    m["zones"].append({"id": "z1", "trust": 2})   # a repeated zone id
    dup = {i.ref for i in validate(m) if i.code == "DUPLICATE_ID"}
    assert dup == {"api", "db", "z1"}


def test_duplicate_id_between_zone_and_element():
    m = base()
    m["elements"][0]["id"] = "z1"
    assert ("z1", "DUPLICATE_ID") in pairs(validate(m))


def test_duplicate_id_reported_once_even_when_used_three_times():
    m = base()
    m["threats"] = [threat("T1"), threat("T1"), threat("T1")]
    assert [i for i in validate(m) if i.code == "DUPLICATE_ID"] == [
        i for i in validate(m) if i.ref == "T1" and i.code == "DUPLICATE_ID"]
    assert len([i for i in validate(m) if i.code == "DUPLICATE_ID"]) == 1


def test_bad_kind_and_unknown_zone_refer_to_the_element():
    m = base()
    m["elements"][0]["kind"] = "robot"
    m["elements"][1]["zone"] = "nowhere"
    got = pairs(validate(m))
    assert ("user", "BAD_KIND") in got
    assert ("api", "UNKNOWN_ZONE") in got


def test_element_without_zone_is_unknown_zone():
    m = base()
    del m["elements"][0]["zone"]
    assert ("user", "UNKNOWN_ZONE") in pairs(validate(m))


def test_unknown_refs_for_flows_and_threats():
    m = base()
    m["flows"] += [
        {"id": "f8", "source": "api", "target": "ghost", "protocol": "tls"},
        {"id": "f9", "source": "ghost", "target": "api", "protocol": "tls"},
    ]
    m["threats"] = [threat("T1", target="ghost"), threat("T2", target="f1"), threat("T3", target="api")]
    got = pairs(validate(m))
    assert {("f8", "UNKNOWN_REF"), ("f9", "UNKNOWN_REF"), ("T1", "UNKNOWN_REF")} <= got
    assert ("T2", "UNKNOWN_REF") not in got      # a flow is a valid threat target
    assert ("T3", "UNKNOWN_REF") not in got      # so is an element


def test_missing_flow_ends_and_threat_target():
    m = base()
    m["flows"].append({"id": "f9", "protocol": "tls"})
    m["threats"] = [{**threat("T1"), "target": None}]
    got = pairs(validate(m))
    assert ("f9", "UNKNOWN_REF") in got and ("T1", "UNKNOWN_REF") in got


@pytest.mark.parametrize("source,target", [
    ("db", "log"),        # store -> store
    ("user", "user"),     # self-loop on an external entity
    ("user", "db"),       # external -> store
    ("db", "user"),       # store -> external
    ("api", "api"),       # self-loop on a process
])
def test_invalid_flows(source, target):
    m = base()
    m["flows"] = [{"id": "f", "source": source, "target": target, "protocol": "tls"}]
    assert ("f", "INVALID_FLOW") in pairs(validate(m))


def test_external_to_external_is_invalid_flow():
    m = base()
    m["elements"].append({"id": "other", "kind": "external_entity", "zone": "z1"})
    m["flows"] = [{"id": "f", "source": "user", "target": "other", "protocol": "tls"}]
    assert ("f", "INVALID_FLOW") in pairs(validate(m))


@pytest.mark.parametrize("source,target", [
    ("user", "api"), ("api", "user"), ("api", "db"), ("db", "api"), ("api", "log"),
])
def test_valid_flows_have_a_process_at_one_end(source, target):
    m = base()
    m["flows"] = [{"id": "f", "source": source, "target": target, "protocol": "tls"}]
    assert "INVALID_FLOW" not in {i.code for i in validate(m)}


@pytest.mark.parametrize("bad", [True, False, 4.0, "4", 0, 6, -1, None, [3], 2.5])
@pytest.mark.parametrize("field", ["likelihood", "impact"])
def test_bad_scores(bad, field):
    t = threat("T1")
    t[field] = bad
    assert ("T1", "BAD_SCORE") in pairs(validate({**base(), "threats": [t]}))


@pytest.mark.parametrize("field", ["likelihood", "impact"])
def test_missing_score_is_bad_score(field):
    t = threat("T1")
    del t[field]
    assert ("T1", "BAD_SCORE") in pairs(validate({**base(), "threats": [t]}))


@pytest.mark.parametrize("good", [1, 2, 3, 4, 5])
def test_good_scores(good):
    assert codes_for([threat("T1", likelihood=good, impact=good)]) == set()


@pytest.mark.parametrize("target,category,expected", [
    ("db", "E", "INAPPLICABLE_CATEGORY"),     # E on a store
    ("db", "R", "INAPPLICABLE_CATEGORY"),     # R on a store that is not a log
    ("db", "S", "INAPPLICABLE_CATEGORY"),
    ("user", "T", "INAPPLICABLE_CATEGORY"),   # T on an external entity
    ("user", "I", "INAPPLICABLE_CATEGORY"),
    ("f1", "S", "INAPPLICABLE_CATEGORY"),     # S on a flow
    ("f1", "R", "INAPPLICABLE_CATEGORY"),
    ("f1", "E", "INAPPLICABLE_CATEGORY"),
    ("log", "R", None),                       # R on a log store is fine
    ("log", "E", "INAPPLICABLE_CATEGORY"),
    ("api", "E", None),
    ("user", "S", None),
    ("f1", "T", None),
    ("api", "s", "BAD_CATEGORY"),
    ("api", "ST", "BAD_CATEGORY"),
    ("api", "", "BAD_CATEGORY"),
    ("api", "X", "BAD_CATEGORY"),
    ("api", None, "BAD_CATEGORY"),
    ("api", ["S"], "BAD_CATEGORY"),
])
def test_categories(target, category, expected):
    assert codes_for([threat("T1", target=target, category=category)]) == (
        {expected} if expected else set())


def test_bad_category_is_not_also_inapplicable():
    assert codes_for([threat("T1", target="db", category="s")]) == {"BAD_CATEGORY"}


def test_decisions_need_words():
    assert codes_for([threat("T1", status="mitigated", mitigation="   \n\t")]) == {"MISSING_MITIGATION"}
    assert codes_for([threat("T1", status="mitigated")]) == {"MISSING_MITIGATION"}
    assert codes_for([threat("T1", status="mitigated", mitigation="")]) == {"MISSING_MITIGATION"}
    assert codes_for([threat("T1", status="accepted", justification=" ")]) == {"MISSING_JUSTIFICATION"}
    assert codes_for([threat("T1", status="accepted")]) == {"MISSING_JUSTIFICATION"}
    # A mitigation text does not justify an acceptance, and the other way round.
    assert codes_for([threat("T1", status="accepted", mitigation="MFA")]) == {"MISSING_JUSTIFICATION"}
    assert codes_for([threat("T1", status="mitigated", justification="fine")]) == {"MISSING_MITIGATION"}


def test_open_threat_needs_no_text():
    assert codes_for([threat("T1", status="open")]) == set()


def test_proper_decisions_raise_nothing():
    ok = [threat("T1", status="mitigated", mitigation="mTLS with a pinned certificate"),
          threat("T2", status="accepted", justification="the switch keeps its own signed log")]
    assert codes_for(ok) == set()


@pytest.mark.parametrize("status", ["wip", "Open", "OPEN", "", None, 3, ["open"]])
def test_bad_status(status):
    assert codes_for([threat("T1", status=status)]) == {"BAD_STATUS"}


def test_validate_is_sorted_and_without_duplicates():
    m = base()
    m["threats"] = [threat("T2", likelihood=9), threat("T1", likelihood=9, impact=0)]
    out = validate(m)
    assert out == sorted(out)
    assert len(out) == len(set(out))
    assert all(isinstance(i, Issue) for i in out)


def test_validate_survives_odd_values():
    m = base()
    m["threats"] = [{"id": ["x"], "target": ["y"], "category": {}, "status": [], "likelihood": {}}]
    m["elements"].append({"id": {"a": 1}, "kind": [], "zone": []})
    validate(m)   # must not raise


# ---------------------------------------------------------------- H08 crossing_flows

def test_crossing_flows_file_order_and_skips_unknown_ends():
    m = base()
    m["flows"] = [
        {"id": "f3", "source": "api", "target": "user", "protocol": "tls"},       # crosses
        {"id": "f0", "source": "api", "target": "ghost", "protocol": "tls"},      # unknown end
        {"id": "f2", "source": "api", "target": "db", "protocol": "tls"},         # same zone
        {"id": "f1", "source": "user", "target": "api", "protocol": "tls"},       # crosses
        {"id": "f9", "source": "ghost", "target": "ghost", "protocol": "tls"},
    ]
    assert crossing_flows(m) == ["f3", "f1"]


def test_crossing_flows_empty_model():
    assert crossing_flows({}) == []


# ---------------------------------------------------------------- coverage_gaps

def test_scope_is_the_crossing_flow_and_its_two_ends_only():
    gaps = coverage_gaps(base())
    assert {g.ref for g in gaps} == {"f1", "user", "api"}      # not f2, not db, not log
    assert len(gaps) == 3 + 2 + 6                              # flow TID, user SR, process all six


def test_scope_follows_the_applicable_letters():
    letters = {}
    for g in coverage_gaps(base()):
        letters.setdefault(g.ref, set()).add(g.category)
    assert letters == {"f1": {"T", "I", "D"}, "user": {"S", "R"}, "api": set("STRIDE")}


def test_a_log_store_at_a_crossing_flow_needs_r():
    m = base()
    m["elements"].append({"id": "collector", "kind": "process", "zone": "z1"})
    m["flows"] = [{"id": "f", "source": "collector", "target": "log", "protocol": "tls"}]
    assert Gap("log", "R") in coverage_gaps(m)
    m["elements"][3]["is_log"] = False
    assert Gap("log", "R") not in coverage_gaps(m)


@pytest.mark.parametrize("status,extra", [
    ("open", {}),
    ("mitigated", {"mitigation": "mTLS"}),
    ("accepted", {"justification": "the switch keeps its own log"}),
])
def test_any_status_covers_a_pair(status, extra):
    m = base()
    m["threats"] = [threat("T1", target="api", category="S", status=status, **extra)]
    assert Gap("api", "S") not in coverage_gaps(m)
    assert Gap("api", "T") in coverage_gaps(m)


def test_a_threat_with_another_category_or_target_does_not_cover():
    m = base()
    m["threats"] = [threat("T1", target="api", category="T"), threat("T2", target="user", category="S")]
    got = coverage_gaps(m)
    assert Gap("api", "S") in got and Gap("user", "S") not in got and Gap("api", "T") not in got


def test_gaps_are_sorted_by_ref_then_stride_order():
    got = coverage_gaps(base())
    assert got == [Gap("api", c) for c in "STRIDE"] + [Gap("f1", c) for c in "TID"] \
        + [Gap("user", c) for c in "SR"]
    assert all(isinstance(g, Gap) for g in got)


def test_all_covered_means_no_gaps():
    m = base()
    n = 0
    for g in coverage_gaps(m):
        n += 1
        m["threats"].append(threat(f"T{n}", target=g.ref, category=g.category))
    assert coverage_gaps(m) == []


def test_no_crossing_flow_means_no_scope():
    m = base()
    m["flows"] = [m["flows"][1]]
    assert coverage_gaps(m) == []


# ---------------------------------------------------------------- policy_findings

def policy_base():
    """base() plus an I threat on the PII store, so only flow findings can show up."""
    m = base()
    m["threats"] = [threat("TI", target="db", category="I")]
    return m


def test_https_in_capitals_passes_and_http_fails():
    m = policy_base()
    for ok in ["https", "HTTPS", "Tls", "mTLS", "sftp", "SSH"]:
        m["flows"][0]["protocol"] = ok
        assert policy_findings(m) == [], ok
    for bad in ["http", "postgres", "ftp", "", None, "httpss", "tcp"]:
        m["flows"][0]["protocol"] = bad
        assert ("f1", "UNENCRYPTED_CROSSING") in pairs(policy_findings(m)), bad
    del m["flows"][0]["protocol"]
    assert ("f1", "UNENCRYPTED_CROSSING") in pairs(policy_findings(m))


def test_only_crossing_flows_are_checked_for_encryption():
    m = policy_base()
    m["flows"][1]["protocol"] = "http"     # f2 stays inside z2
    assert policy_findings(m) == []


def test_inbound_flow_needs_authentication():
    m = policy_base()
    del m["flows"][0]["authenticated"]     # missing key counts as not authenticated
    assert ("f1", "UNAUTHENTICATED_INBOUND") in pairs(policy_findings(m))
    m["flows"][0]["authenticated"] = False
    assert ("f1", "UNAUTHENTICATED_INBOUND") in pairs(policy_findings(m))
    m["flows"][0]["authenticated"] = "true"      # a string is not the boolean true
    assert ("f1", "UNAUTHENTICATED_INBOUND") in pairs(policy_findings(m))
    m["flows"][0]["authenticated"] = True
    assert policy_findings(m) == []


def test_outbound_and_equal_trust_flows_are_not_flagged():
    m = policy_base()
    m["flows"] = [{"id": "out", "source": "api", "target": "user", "protocol": "https"}]   # 3 -> 1
    assert policy_findings(m) == []
    m["zones"] = [{"id": "z1", "trust": 2}, {"id": "z2", "trust": 2}]                      # equal
    m["flows"] = [{"id": "eq", "source": "user", "target": "api", "protocol": "https"}]
    assert policy_findings(m) == []


def test_unauthenticated_check_needs_known_trust():
    m = policy_base()
    m["zones"] = [{"id": "z1"}, {"id": "z2", "trust": 3}]
    del m["flows"][0]["authenticated"]
    assert policy_findings(m) == []


def test_pii_store_needs_an_i_threat_in_any_status():
    m = base()
    assert ("db", "PII_STORE_WITHOUT_I_THREAT") in pairs(policy_findings(m))
    m["threats"] = [threat("T1", target="db", category="T")]              # other category
    assert ("db", "PII_STORE_WITHOUT_I_THREAT") in pairs(policy_findings(m))
    m["threats"] = [threat("T2", target="log", category="I")]             # other target
    assert ("db", "PII_STORE_WITHOUT_I_THREAT") in pairs(policy_findings(m))
    for status, extra in [("open", {}), ("mitigated", {"mitigation": "encrypted at rest"}),
                          ("accepted", {"justification": "no PII in this table"})]:
        m["threats"] = [threat("T3", target="db", category="I", status=status, **extra)]
        assert policy_findings(m) == [], status


def test_only_data_stores_with_holds_pii_true_are_flagged():
    m = base()
    m["elements"][1]["holds_pii"] = True        # a process: not a store
    m["elements"][3]["holds_pii"] = False
    assert pairs(policy_findings(m)) == {("db", "PII_STORE_WITHOUT_I_THREAT")}


def test_policy_findings_are_sorted_by_ref_then_code():
    m = base()
    m["flows"][0].update(protocol="http")
    del m["flows"][0]["authenticated"]
    out = policy_findings(m)
    assert [(i.ref, i.code) for i in out] == [
        ("db", "PII_STORE_WITHOUT_I_THREAT"),
        ("f1", "UNAUTHENTICATED_INBOUND"),
        ("f1", "UNENCRYPTED_CROSSING"),
    ]


# ---------------------------------------------------------------- rank

def test_rank_levels_at_the_boundaries():
    # Scores of 7 and 14 cannot occur with integers 1-5, so the reachable edges are
    # 15 (high) / 12 (medium) and 8 (medium) / 6 (low).
    m = base()
    m["threats"] = [
        threat("A", likelihood=5, impact=3),   # 15 high
        threat("B", likelihood=2, impact=4),   # 8 medium
        threat("C", likelihood=1, impact=5),   # 5 low
        threat("D", likelihood=2, impact=3),   # 6 low
        threat("E", likelihood=3, impact=4),   # 12 medium
        threat("F", likelihood=3, impact=5),   # 15 high
        threat("G", likelihood=1, impact=1),   # 1 low
        threat("H", likelihood=5, impact=5),   # 25 high
    ]
    got = {r.id: (r.score, r.level) for r in rank(m)}
    assert got == {"A": (15, "high"), "F": (15, "high"), "H": (25, "high"),
                   "B": (8, "medium"), "E": (12, "medium"),
                   "C": (5, "low"), "D": (6, "low"), "G": (1, "low")}


def test_rank_open_only():
    m = base()
    m["threats"] = [
        threat("T1", likelihood=5, impact=5, status="mitigated", mitigation="x"),
        threat("T2", likelihood=5, impact=5, status="accepted", justification="x"),
        threat("T3", likelihood=1, impact=1, status="wip"),
        threat("T4", likelihood=1, impact=1),
    ]
    assert [r.id for r in rank(m)] == ["T4"]


def test_rank_skips_open_threats_with_invalid_scores():
    m = base()
    m["threats"] = [threat("T1", likelihood=True, impact=5), threat("T2", likelihood=4.0, impact=5),
                    threat("T3", likelihood="5", impact=5), threat("T4", likelihood=5, impact=None),
                    threat("T5", likelihood=6, impact=2), threat("T6", likelihood=1, impact=1)]
    assert [r.id for r in rank(m)] == ["T6"]


def test_rank_ties_break_on_impact_then_natural_id():
    m = base()
    m["threats"] = [
        threat("T10", likelihood=3, impact=3),
        threat("T2", likelihood=3, impact=3),
        threat("T1", likelihood=3, impact=3),
        threat("T9", likelihood=4, impact=3),     # 12, impact 3
        threat("T8", likelihood=3, impact=4),     # 12, impact 4: first
        threat("T20", likelihood=5, impact=5),
    ]
    assert [r.id for r in rank(m)] == ["T20", "T8", "T9", "T1", "T2", "T10"]


def test_rank_natural_id_with_other_shapes():
    m = base()
    m["threats"] = [threat(i, likelihood=2, impact=2) for i in ["X-10", "X-2", "A5", "B", "A10", "T2"]]
    assert [r.id for r in rank(m)] == ["A5", "A10", "B", "T2", "X-2", "X-10"]


def test_rank_result_types():
    m = base()
    m["threats"] = [threat("T1", likelihood=5, impact=3)]
    assert rank(m) == [RankedThreat(id="T1", score=15, level="high")]


# ---------------------------------------------------------------- H13 CLI

def write(tmp_path, text):
    p = tmp_path / "m.yaml"
    p.write_text(text)
    return str(p)


def test_cli_exit_2_for_missing_file_and_bad_file(tmp_path, capsys):
    assert main([str(tmp_path / "nope.yaml")]) == 2
    assert main([write(tmp_path, "- a\n")]) == 2
    assert main([write(tmp_path, "zones: !!python/object/apply:os.system ['echo pwned']\n")]) == 2
    assert capsys.readouterr().out == ""        # no JSON on a load failure, and nothing ran


def test_cli_exit_2_for_wrong_argument_count(capsys):
    assert main([]) == 2
    assert main(["a.yaml", "b.yaml"]) == 2


def test_cli_exit_1_and_json_shape_for_a_model_with_gaps(tmp_path, capsys):
    p = tmp_path / "m.yaml"
    import yaml
    p.write_text(yaml.safe_dump(base()))
    assert main([str(p)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert set(out) == {"issues", "gaps", "policy", "ranked"}
    assert all(isinstance(v, list) for v in out.values())
    assert out["gaps"] and all(set(g) == {"ref", "category"} for g in out["gaps"])
    assert {"ref": "api", "category": "S"} in out["gaps"]


def test_cli_exit_1_for_issues_and_for_policy_findings(tmp_path, capsys):
    import yaml
    m = base()
    m["elements"][0]["kind"] = "robot"
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(m))
    assert main([str(p)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["issues"] and set(out["issues"][0]) == {"ref", "code", "message"}

    # Fully covered model that only has a policy finding (plaintext crossing) still exits 1.
    m = base()
    m["flows"][0]["protocol"] = "http"
    n = 0
    for g in coverage_gaps(m):
        n += 1
        m["threats"].append(threat(f"T{n}", target=g.ref, category=g.category))
    m["threats"].append(threat("TI", target="db", category="I"))
    p.write_text(yaml.safe_dump(m))
    assert main([str(p)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["issues"] == [] and out["gaps"] == [] and out["policy"]


def test_cli_exit_0_for_a_clean_model(tmp_path, capsys):
    p = write(tmp_path, "zones:\n  - {id: z, trust: 1}\nelements:\n  - {id: p, kind: process, zone: z}\n")
    assert main([p]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out == {"issues": [], "gaps": [], "policy": [], "ranked": []}


def test_cli_ranked_objects_have_the_dataclass_fields(tmp_path, capsys):
    import yaml
    m = base()
    m["threats"] = [threat("T1", likelihood=5, impact=3)]
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(m))
    main([str(p)])
    assert json.loads(capsys.readouterr().out)["ranked"] == [{"id": "T1", "score": 15, "level": "high"}]


def test_cli_as_a_real_process():
    """python -m tmcheck from the repository root, the way a CI job would run it."""
    run = subprocess.run([sys.executable, "-m", "tmcheck", str(MODEL)], cwd=ROOT,
                         capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stdout + run.stderr
    assert set(json.loads(run.stdout)) == {"issues", "gaps", "policy", "ranked"}
    missing = subprocess.run([sys.executable, "-m", "tmcheck", "no_such_file.yaml"], cwd=ROOT,
                             capture_output=True, text=True, timeout=30)
    assert missing.returncode == 2


# ---------------------------------------------------------------- H14 the Rawaj model

def test_rawaj_model_passes_the_checker():
    m = load_model(MODEL)
    assert validate(m) == []
    assert coverage_gaps(m) == []
    assert policy_findings(m) == []


def test_rawaj_model_keeps_its_shape_and_has_unique_real_titles():
    m = load_model(MODEL)
    assert (len(m["zones"]), len(m["elements"]), len(m["flows"])) == (5, 9, 8)
    assert len(m["threats"]) >= 26 + 11
    titles = [t["title"].strip().lower() for t in m["threats"]]
    assert len(titles) == len(set(titles))
    assert all(len(t) >= 15 for t in titles)
    ids = [x["id"] for s in ("zones", "elements", "flows", "threats") for x in m[s]]
    assert len(ids) == len(set(ids))


def test_rawaj_console_to_case_db_is_not_plaintext():
    m = load_model(MODEL)
    f08 = next(f for f in m["flows"] if f["id"] == "f08")
    assert (f08["source"], f08["target"]) == ("analyst_console", "case_db")
    assert f08["protocol"].lower() in ("https", "tls", "mtls", "sftp", "ssh")
