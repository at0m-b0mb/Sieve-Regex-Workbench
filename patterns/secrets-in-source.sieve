{
  "schema": 1,
  "name": "Secrets in source",
  "intent": "Key material committed by mistake. A triage net, not a detection.",
  "join": "any",
  "ignore_case": false,
  "dot_matches_newline": false,
  "multiline": true,
  "anchor_start": false,
  "anchor_end": false,
  "scope": "line",
  "rules": [
    {
      "kind": "find",
      "pattern": "\\b(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\\b",
      "label": "aws access key id",
      "literal": false,
      "whole_word": false,
      "capture": false,
      "capture_name": "",
      "ignore_case": null,
      "enabled": true,
      "repeat": {
        "mode": "once",
        "minimum": 1,
        "maximum": 1,
        "greedy": true
      },
      "note": "Finds the ID, never the secret, and cannot tell you whether the key is live. Treat every hit as live until proven dead.",
      "source": "aws_access_key"
    },
    {
      "kind": "find",
      "pattern": "\\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,255}\\b",
      "label": "github token",
      "literal": false,
      "whole_word": false,
      "capture": false,
      "capture_name": "",
      "ignore_case": null,
      "enabled": true,
      "repeat": {
        "mode": "once",
        "minimum": 1,
        "maximum": 1,
        "greedy": true
      },
      "note": "GitHub revokes tokens it sees pushed publicly, so a hit in a public repository may already be dead \u2014 and may not be.",
      "source": "github_token"
    },
    {
      "kind": "find",
      "pattern": "-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
      "label": "private key block",
      "literal": false,
      "whole_word": false,
      "capture": false,
      "capture_name": "",
      "ignore_case": null,
      "enabled": true,
      "repeat": {
        "mode": "once",
        "minimum": 1,
        "maximum": 1,
        "greedy": true
      },
      "note": "Matches the header only. An encrypted key still needs its passphrase; an unencrypted one does not.",
      "source": "private_key"
    },
    {
      "kind": "find",
      "pattern": "\\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|amqp|mssql)://[^:\\s/]+:[^@\\s/]+@[^\\s/]+",
      "label": "database connection string",
      "literal": false,
      "whole_word": false,
      "capture": false,
      "capture_name": "",
      "ignore_case": true,
      "enabled": true,
      "repeat": {
        "mode": "once",
        "minimum": 1,
        "maximum": 1,
        "greedy": true
      },
      "note": "Only catches credentials embedded in the URI. A driver reading a password from the environment leaves no string to find.",
      "source": "connection_string"
    },
    {
      "kind": "exclude",
      "pattern": "(?:example|sample|dummy|placeholder|changeme|xxxx)",
      "label": "anything that looks like a placeholder",
      "literal": false,
      "whole_word": false,
      "capture": false,
      "capture_name": "",
      "ignore_case": true,
      "enabled": true,
      "repeat": {
        "mode": "once",
        "minimum": 1,
        "maximum": 1,
        "greedy": true
      },
      "note": "",
      "source": ""
    }
  ],
  "proof": [
    {
      "text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REALKEY",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "-----BEGIN OPENSSH PRIVATE KEY-----",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "postgresql://admin:s3cr3t@db.internal:5432/production",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
      "expect": "should_not_match",
      "note": "the vendor's own example key"
    },
    {
      "text": "DEBUG=false",
      "expect": "should_not_match",
      "note": ""
    }
  ],
  "sample": "secrets"
}
