import os
import pytest
from src.evaluation.rigorous_validation_suite import RigorousValidationSuite


def test_rigorous_validation_suite_checks():
    suite = RigorousValidationSuite()
    report = suite.run_all_checks()

    assert report["all_passed"] is True
    assert len(report["checks"]) == 6

    # Verify every check passed individually
    for check in report["checks"]:
        assert check["passed"] is True, f"Check failed: {check['name']}"

    assert os.path.exists("data/processed/rigorous_validation_report.json")
