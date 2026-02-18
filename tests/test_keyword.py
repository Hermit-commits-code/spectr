# test_keyword.py
from skopos.checker_logic import check_for_typosquatting
passed, match = check_for_typosquatting("requests-ultra")
print(f"Flagged: {passed} | Match: {match}")