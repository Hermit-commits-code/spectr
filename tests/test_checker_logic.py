from skopos import checker_logic as cl


def test_levenshtein_basic():
    assert cl.levenshtein_distance('kitten', 'sitting') == 3
    assert cl.levenshtein_distance('flaw', 'lawn') == 2


def test_calculate_entropy():
    assert cl.calculate_entropy('') == 0.0
    # low entropy string
    assert cl.calculate_entropy('aaaaaa') == 0.0
    # higher entropy for varied chars
    e = cl.calculate_entropy('abcABC123!')
    assert e > 2.0


def test_check_for_typosquatting_keyword(tmp_path, monkeypatch):
    # Provide a small custom target mapping
    custom = {'requests': 1}
    # keyword-stuffing: requests-ultra should be flagged
    flagged, reason = cl.check_for_typosquatting('requests-ultra', custom_targets=custom)
    assert flagged
    assert 'requests' in reason


def test_get_dependencies_parsing():
    data = {'info': {'requires_dist': ['requests>=2.0', 'urllib3; extra == "security"', 'pkg-name (>=1.0)']}}
    deps = cl.get_dependencies(data)
    assert 'requests' in deps
    assert 'pkg-name' in deps
    assert 'urllib3' not in deps  # extra conditional should be ignored


def test_calculate_skopos_score_override():
    # Typosquatting override should force 0
    results = {'Typosquatting': (True, 'requests')}
    assert cl.calculate_skopos_score(results) == 0
