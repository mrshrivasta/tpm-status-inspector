"""
Security Engine — TPM Status Inspector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Collects REAL TPM state from this machine:
  1. Enumerates /sys/class/tpm/tpmN entries (kernel-registered TPM chips)
  2. Checks for /dev/tpmN (raw) and /dev/tpmrmN (resource-managed) device nodes
  3. Reads real device-node permission bits via os.stat
  4. Attempts to read a TPM 1.2-style version file where present
  5. Checks for tpm2-tools availability (tpm2_getcap / tpm2_pcrread)

No sample TPM data is ever fabricated. A system with no TPM (common in
containers/VMs) simply yields zero devices, which is the correct, real
result for that environment.
"""
import os
import shutil
import stat as statmod
import time
from app.detection_rules import (
    ALL_RULES,
    rule_no_tpm_present,
    rule_tpm_device_node_missing,
    rule_tpm_resource_manager_missing,
    rule_tpm_tooling_unavailable,
    rule_legacy_tpm_version,
    rule_tpm_device_node_overly_permissive,
)

TPM_CLASS_DIR = "/sys/class/tpm"


def _read_text(path):
    try:
        with open(path, "r") as fh:
            return fh.read().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return None


class ScanEngine:
    """target_path is unused (kept for interface parity across projects)."""

    def __init__(self, target_path=None, max_depth=None, excludes=None, max_files=None):
        self.errors_count = 0
        self.findings = []
        self.devices_scanned = 0

    def run(self):
        start = time.time()
        tpm_present = os.path.isdir(TPM_CLASS_DIR) and bool(os.listdir(TPM_CLASS_DIR)) if os.path.isdir(TPM_CLASS_DIR) else False
        tpm2_tools_available = shutil.which("tpm2_getcap") is not None or shutil.which("tpm2_pcrread") is not None

        status = {"tpm_present": tpm_present}
        no_tpm_finding = rule_no_tpm_present(status)
        if no_tpm_finding:
            self._record(no_tpm_finding, "/sys/class/tpm", None)

        devices = self._collect_devices() if tpm_present else []
        for device in devices:
            self.devices_scanned += 1
            for rule in (rule_tpm_device_node_missing, rule_tpm_resource_manager_missing,
                         rule_legacy_tpm_version, rule_tpm_device_node_overly_permissive):
                try:
                    result = rule(device)
                except Exception:
                    self.errors_count += 1
                    continue
                if result:
                    self._record(result, device["sysfs_path"], device.get("dev_node_mode"))

        tooling_finding = rule_tpm_tooling_unavailable(tpm2_tools_available)
        if tooling_finding:
            self._record(tooling_finding, "tpm2-tools (tooling)", None)

        elapsed = time.time() - start
        return {
            "files_scanned": self.devices_scanned,
            "dirs_scanned": 1 if tpm_present else 0,
            "errors_count": self.errors_count,
            "tpm_present": tpm_present,
            "tpm2_tools_available": tpm2_tools_available,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _collect_devices(self):
        devices = []
        try:
            names = sorted(os.listdir(TPM_CLASS_DIR))
        except (FileNotFoundError, PermissionError, OSError):
            self.errors_count += 1
            return devices

        for name in names:  # e.g. "tpm0"
            sysfs_path = os.path.join(TPM_CLASS_DIR, name)
            dev_path = f"/dev/{name}"
            rm_name = name.replace("tpm", "tpmrm", 1) if name.startswith("tpm") else f"{name}rm"
            resource_manager_path = f"/dev/{rm_name}"

            version_major = _read_text(os.path.join(sysfs_path, "tpm_version_major"))
            has_legacy_attrs = any(
                os.path.exists(os.path.join(sysfs_path, f)) for f in ("active", "enabled", "owned")
            )
            version = version_major or ("1.2" if has_legacy_attrs else "2.0")

            dev_node_exists = os.path.exists(dev_path)
            dev_node_mode = None
            dev_node_world_accessible = False
            if dev_node_exists:
                try:
                    st = os.stat(dev_path)
                    dev_node_mode = oct(st.st_mode & 0o777)[2:].zfill(3)
                    dev_node_world_accessible = bool(st.st_mode & (statmod.S_IROTH | statmod.S_IWOTH))
                except (PermissionError, OSError):
                    self.errors_count += 1

            devices.append({
                "sysfs_path": sysfs_path,
                "dev_path": dev_path,
                "resource_manager_path": resource_manager_path,
                "dev_node_exists": dev_node_exists,
                "resource_manager_exists": os.path.exists(resource_manager_path),
                "dev_node_mode": dev_node_mode,
                "dev_node_world_accessible": dev_node_world_accessible,
                "version": version,
            })
        return devices

    def _record(self, finding, path, extra):
        finding["file_path"] = path
        finding["permissions_octal"] = extra or "-"
        finding["owner_uid"] = None
        finding["owner_gid"] = None
        self.findings.append(finding)
