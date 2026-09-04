"""
Detection Rules — TPM Status Inspector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects REAL data collected from this machine's TPM interface
(/sys/class/tpm, /dev/tpm*, and tpm2-tools where available). No sample TPM
data is ever generated — a system with no TPM chip (very common in
containers, VMs, and older hardware) correctly reports that absence, which
is the real result for that environment.
"""

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


def rule_no_tpm_present(status):
    """TPM-001: No TPM device was found under /sys/class/tpm on this
    system. A TPM provides hardware-backed key storage and measured boot
    attestation; its absence weakens the platform's hardware root of trust
    (not itself a vulnerability if genuinely absent, but worth tracking)."""
    if not status["tpm_present"]:
        return {
            "rule_id": "TPM-001",
            "rule_name": "No TPM Device Found",
            "severity": SEVERITY_MEDIUM,
            "description": (
                "No TPM device was found under /sys/class/tpm. This is "
                "expected on many containers, VMs, and older hardware. "
                "Where a hardware root of trust is required (disk encryption "
                "key sealing, measured boot, remote attestation), a TPM is "
                "necessary and is not present on this system."
            ),
        }
    return None


def rule_tpm_device_node_missing(device):
    """TPM-002: A TPM chip is registered in sysfs, but its /dev/tpmN
    character device node is missing — user-space cannot talk to the TPM
    even though the kernel driver detected it."""
    if not device["dev_node_exists"]:
        return {
            "rule_id": "TPM-002",
            "rule_name": "TPM Device Node Missing",
            "severity": SEVERITY_LOW,
            "description": (
                f"{device['sysfs_path']} is registered but {device['dev_path']} "
                f"does not exist. User-space applications cannot communicate "
                f"with this TPM."
            ),
        }
    return None


def rule_tpm_resource_manager_missing(device):
    """TPM-003: The kernel TPM resource manager device (/dev/tpmrmN) is not
    present. Without it, applications must talk to the raw /dev/tpmN device
    directly, which does not support safe concurrent access from multiple
    processes and is more error-prone."""
    if device["dev_node_exists"] and not device["resource_manager_exists"]:
        return {
            "rule_id": "TPM-003",
            "rule_name": "TPM Resource Manager Device Missing",
            "severity": SEVERITY_LOW,
            "description": (
                f"{device['resource_manager_path']} is not present. Software "
                f"should prefer the kernel resource-managed TPM device over "
                f"raw /dev/tpm* access for safe concurrent use."
            ),
        }
    return None


def rule_tpm_tooling_unavailable(tpm2_tools_available):
    """TPM-004: tpm2-tools is not installed, so PCR banks, algorithm
    capabilities, and attestation-relevant properties cannot be inspected
    even where a TPM 2.0 chip is present. Informational only."""
    if not tpm2_tools_available:
        return {
            "rule_id": "TPM-004",
            "rule_name": "tpm2-tools Not Available",
            "severity": SEVERITY_LOW,
            "description": (
                "tpm2-tools (tpm2_getcap / tpm2_pcrread) is not installed, so "
                "PCR values and TPM 2.0 capabilities cannot be inspected even "
                "where a TPM chip is detected. This is an environment "
                "limitation, not a vulnerability."
            ),
        }
    return None


def rule_legacy_tpm_version(device):
    """TPM-005: The detected TPM reports itself as TPM 1.2 (legacy). TPM 1.2
    uses SHA-1-only PCR banks and lacks TPM 2.0 features such as enhanced
    authorization policies and algorithm agility."""
    if device.get("version") == "1.2":
        return {
            "rule_id": "TPM-005",
            "rule_name": "Legacy TPM 1.2 Chip Detected",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"{device['sysfs_path']} reports TPM version 1.2 (legacy). "
                f"TPM 1.2 is limited to SHA-1 PCR banks and lacks TPM 2.0 "
                f"features. Consider migrating to TPM 2.0 hardware where possible."
            ),
        }
    return None


def rule_tpm_device_node_overly_permissive(device):
    """TPM-006: /dev/tpmN or /dev/tpmrmN is readable/writable by users
    outside the expected 'tss'/root ownership model — any local user could
    send raw commands to or read responses from the TPM, undermining
    isolation between processes/users."""
    if device["dev_node_exists"] and device.get("dev_node_world_accessible"):
        return {
            "rule_id": "TPM-006",
            "rule_name": "TPM Device Node Overly Permissive",
            "severity": SEVERITY_HIGH,
            "description": (
                f"{device['dev_path']} is readable/writable by users outside "
                f"the expected owner/group (mode {device.get('dev_node_mode', '?')}). "
                f"Any local user could interact directly with the TPM."
            ),
        }
    return None


ALL_RULES = [
    rule_no_tpm_present,
    rule_tpm_device_node_missing,
    rule_tpm_resource_manager_missing,
    rule_tpm_tooling_unavailable,
    rule_legacy_tpm_version,
    rule_tpm_device_node_overly_permissive,
]
