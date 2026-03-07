"""
Cryptographic Posture Auditor
================================
Checks: SSH key size, TLS versions, cipher suites, IPsec config, key chains
"""

import re
from typing import List, Dict, Any
from modules.base import BaseAuditor


class CryptoPostureAuditor(BaseAuditor):

    WEAK_CIPHERS_SSH = ["aes128-cbc", "3des-cbc", "arcfour", "blowfish"]
    WEAK_HMACS = ["hmac-md5", "hmac-sha1-96", "hmac-md5-96"]

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_ssh_key_size()
        self.check_ssh_ciphers()
        self.check_tls_version()
        self.check_ipsec_transforms()
        self.check_key_chains()
        self.check_crypto_isakmp()
        return self.findings

    def check_ssh_key_size(self):
        rsa_lines = self.config.find_lines(r"crypto key generate rsa.*modulus\s+(\d+)")
        for l in rsa_lines:
            m = re.search(r"modulus\s+(\d+)", l)
            if m:
                bits = int(m.group(1))
                if bits < 2048:
                    self.finding("CRYPTO-001", f"SSH RSA key too small ({bits} bits)",
                        self.SEVERITY_HIGH, "Cryptographic Posture",
                        f"SSH RSA key is {bits} bits (minimum: 2048). Keys below 2048 bits "
                        "are considered weak and may be factored.",
                        [f"RSA key: {bits} bits"],
                        "Regenerate: crypto key generate rsa modulus 4096",
                        ["CIS Cisco IOS Benchmark 7.1", "NIST SP 800-131A"])
        # Also check from ip ssh config
        ssh_ver = self.config.find_lines(r"^ip ssh")
        # No explicit key size found — check if SSH is configured at all
        if not rsa_lines and self.config.has_line(r"^ip ssh version"):
            self.finding("CRYPTO-002", "SSH RSA key size not verifiable from config",
                self.SEVERITY_LOW, "Cryptographic Posture",
                "Cannot determine SSH RSA key size from the running config. "
                "Verify with 'show crypto key mypubkey rsa' that keys are ≥2048 bits.",
                remediation="Verify: show crypto key mypubkey rsa",
                references=["CIS Cisco IOS Benchmark 7.1"])

    def check_ssh_ciphers(self):
        cipher_line = self.config.get_value(r"ip ssh.*cipher.*server\s+(.*)", default="")
        if cipher_line:
            for wc in self.WEAK_CIPHERS_SSH:
                if wc.lower() in cipher_line.lower():
                    self.finding("CRYPTO-003", f"Weak SSH cipher enabled: {wc}",
                        self.SEVERITY_HIGH, "Cryptographic Posture",
                        f"SSH cipher '{wc}' is enabled. CBC-mode and legacy ciphers "
                        "have known vulnerabilities.",
                        [f"Cipher config: {cipher_line}"],
                        "Configure only strong ciphers: "
                        "ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr",
                        ["CIS Cisco IOS Benchmark 7.2", "NIST SP 800-131A"])
                    break
        hmac_line = self.config.get_value(r"ip ssh.*mac.*server\s+(.*)", default="")
        if hmac_line:
            for wh in self.WEAK_HMACS:
                if wh.lower() in hmac_line.lower():
                    self.finding("CRYPTO-004", f"Weak SSH HMAC enabled: {wh}",
                        self.SEVERITY_MEDIUM, "Cryptographic Posture",
                        f"SSH HMAC '{wh}' is enabled. MD5-based HMACs are deprecated.",
                        remediation="Configure: ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-512",
                        references=["CIS Cisco IOS Benchmark 7.3"])
                    break

    def check_tls_version(self):
        tls_lines = self.config.find_lines(r"(ssl|tls)\s*(version|protocol)")
        for l in tls_lines:
            l_lower = l.lower()
            if "1.0" in l_lower or "sslv3" in l_lower or "ssl3" in l_lower:
                self.finding("CRYPTO-005", "Deprecated TLS/SSL version enabled",
                    self.SEVERITY_HIGH, "Cryptographic Posture",
                    f"Config contains deprecated TLS/SSL version: {l.strip()}. "
                    "TLS 1.0, 1.1, and SSLv3 have known vulnerabilities.",
                    [l.strip()],
                    "Configure minimum TLS 1.2. Prefer TLS 1.3 where supported.",
                    ["NIST SP 800-52 Rev 2", "CIS Cisco IOS Benchmark 7.4"])

    def check_ipsec_transforms(self):
        transforms = self.config.find_lines(r"crypto ipsec transform-set")
        weak_transforms = []
        for t in transforms:
            t_lower = t.lower()
            if any(w in t_lower for w in ["des ", "3des", "md5", "ah-md5"]):
                weak_transforms.append(t.strip())
        if weak_transforms:
            self.finding("CRYPTO-006", "Weak IPsec transform sets configured",
                self.SEVERITY_HIGH, "Cryptographic Posture",
                f"{len(weak_transforms)} IPsec transform set(s) use weak algorithms "
                "(DES, 3DES, MD5).",
                weak_transforms,
                "Use AES-256-GCM with SHA-256/SHA-384: "
                "crypto ipsec transform-set <name> esp-aes 256 esp-sha256-hmac",
                ["CIS Cisco IOS Benchmark 7.5"])

    def check_key_chains(self):
        keychains = self.config.get_section("key chain")
        for kc, lines in keychains.items():
            for l in lines:
                if "key-string" in l.lower():
                    # Check if plaintext
                    if re.search(r"key-string\s+[^0-9]", l) and "7 " not in l:
                        self.finding("CRYPTO-007", f"Plaintext key-string in {kc}",
                            self.SEVERITY_HIGH, "Cryptographic Posture",
                            f"Key chain {kc} contains a plaintext key string.",
                            remediation="Use encrypted key storage or TACACS+ for key management.",
                            references=["Cisco IOS — Key Chain Security"])
                        break

    def check_crypto_isakmp(self):
        isakmp = self.config.find_lines(r"crypto isakmp policy")
        for policy in isakmp:
            policy_section = self.config.get_section(policy)
            for sec, lines in policy_section.items():
                for l in lines:
                    l_lower = l.lower()
                    if "encryption des" in l_lower or "encryption 3des" in l_lower:
                        self.finding("CRYPTO-008", f"Weak ISAKMP encryption in {sec}",
                            self.SEVERITY_HIGH, "Cryptographic Posture",
                            f"ISAKMP policy uses weak encryption: {l.strip()}",
                            [l.strip()],
                            "Use: encryption aes 256",
                            ["CIS Cisco IOS Benchmark 7.6"])
                    if "hash md5" in l_lower:
                        self.finding("CRYPTO-009", f"ISAKMP using MD5 hash in {sec}",
                            self.SEVERITY_HIGH, "Cryptographic Posture",
                            f"ISAKMP policy uses MD5 hashing: {l.strip()}",
                            [l.strip()],
                            "Use: hash sha256 or sha384",
                            ["CIS Cisco IOS Benchmark 7.7"])
                    if "group 1" in l_lower or "group 2" in l_lower:
                        self.finding("CRYPTO-010", f"Weak DH group in ISAKMP: {sec}",
                            self.SEVERITY_HIGH, "Cryptographic Posture",
                            f"DH group 1/2 (768/1024 bits) is weak: {l.strip()}",
                            [l.strip()],
                            "Use: group 14 (2048-bit) or higher. Prefer group 19/20 (ECDH).",
                            ["NIST SP 800-131A — DH Group Requirements"])
