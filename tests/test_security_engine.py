"""Tests for the TPM Status Inspector's Security Engine and rules.

Rule-level tests use synthetic status/device dicts (no risk to real TPM
hardware). Engine-level tests run the REAL collection against this host's
/sys/class/tpm, /dev/tpm*, and tpm2-tools availability — no mocking of the
underlying sources. On a machine with no TPM (this sandbox), the correct,
real result is tpm_present=False, which the tests verify is handled
gracefully rather than crashing.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine
from app.detection_rules import (
    rule_no_tpm_present,
    rule_tpm_device_node_missing,
    rule_tpm_resource_manager_missing,
    rule_tpm_tooling_unavailable,
    rule_legacy_tpm_version,
    rule_tpm_device_node_overly_permissive,
)


def device(sysfs_path="/sys/class/tpm/tpm0", dev_path="/dev/tpm0", resource_manager_path="/dev/tpmrm0",
           dev_node_exists=True, resource_manager_exists=True, dev_node_mode="660",
           dev_node_world_accessible=False, version="2.0"):
    return {
        "sysfs_path": sysfs_path, "dev_path": dev_path, "resource_manager_path": resource_manager_path,
        "dev_node_exists": dev_node_exists, "resource_manager_exists": resource_manager_exists,
        "dev_node_mode": dev_node_mode, "dev_node_world_accessible": dev_node_world_accessible,
        "version": version,
    }


def test_no_tpm_present_flagged():
    result = rule_no_tpm_present({"tpm_present": False})
    assert result is not None
    assert result["rule_id"] == "TPM-001"


def test_tpm_present_not_flagged():
    result = rule_no_tpm_present({"tpm_present": True})
    assert result is None


def test_missing_dev_node_flagged():
    d = device(dev_node_exists=False)
    result = rule_tpm_device_node_missing(d)
    assert result is not None
    assert result["rule_id"] == "TPM-002"


def test_present_dev_node_not_flagged():
    d = device(dev_node_exists=True)
    result = rule_tpm_device_node_missing(d)
    assert result is None


def test_missing_resource_manager_flagged():
    d = device(dev_node_exists=True, resource_manager_exists=False)
    result = rule_tpm_resource_manager_missing(d)
    assert result is not None
    assert result["rule_id"] == "TPM-003"


def test_present_resource_manager_not_flagged():
    d = device(dev_node_exists=True, resource_manager_exists=True)
    result = rule_tpm_resource_manager_missing(d)
    assert result is None


def test_tooling_unavailable_flagged():
    result = rule_tpm_tooling_unavailable(tpm2_tools_available=False)
    assert result is not None
    assert result["rule_id"] == "TPM-004"


def test_tooling_available_not_flagged():
    result = rule_tpm_tooling_unavailable(tpm2_tools_available=True)
    assert result is None


def test_legacy_version_flagged():
    d = device(version="1.2")
    result = rule_legacy_tpm_version(d)
    assert result is not None
    assert result["rule_id"] == "TPM-005"


def test_tpm2_version_not_flagged():
    d = device(version="2.0")
    result = rule_legacy_tpm_version(d)
    assert result is None


def test_world_accessible_device_flagged_high():
    d = device(dev_node_exists=True, dev_node_world_accessible=True, dev_node_mode="666")
    result = rule_tpm_device_node_overly_permissive(d)
    assert result is not None
    assert result["severity"] == "high"


def test_restricted_device_not_flagged():
    d = device(dev_node_exists=True, dev_node_world_accessible=False, dev_node_mode="660")
    result = rule_tpm_device_node_overly_permissive(d)
    assert result is None


def test_real_engine_runs_against_live_host_without_crashing():
    """Sanity check against this host's real TPM interfaces."""
    engine = ScanEngine()
    result = engine.run()
    assert isinstance(result["findings"], list)
    assert isinstance(result["tpm_present"], bool)
    assert isinstance(result["tpm2_tools_available"], bool)


def test_real_engine_no_tpm_yields_tpm001_finding_or_clean_tpm():
    engine = ScanEngine()
    result = engine.run()
    if not result["tpm_present"]:
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "TPM-001" in rule_ids
