{
  "schema": 1,
  "name": "SSH brute force",
  "intent": "Repeated password failures from a routable address, minus our own monitoring.",
  "join": "sequence",
  "ignore_case": false,
  "dot_matches_newline": false,
  "multiline": true,
  "anchor_start": false,
  "anchor_end": false,
  "scope": "line",
  "rules": [
    {
      "kind": "find",
      "pattern": "Failed password for (?:invalid user )?(?P<user>\\w+)",
      "label": "an ssh password failure",
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
      "note": "",
      "source": ""
    },
    {
      "kind": "require",
      "pattern": "\\b(?!10\\.)(?!127\\.)(?!169\\.254\\.)(?!192\\.168\\.)(?!172\\.(?:1[6-9]|2\\d|3[01])\\.)(?!0\\.)(?!22[4-9]\\.)(?!2[3-5]\\d\\.)(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}\\b",
      "label": "ipv4, routable only",
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
      "note": "Built from negative lookaheads, so RE2 and POSIX grep cannot run it. Sieve will offer you the two-pass pipeline instead.",
      "source": "ipv4_public"
    },
    {
      "kind": "exclude",
      "pattern": "healthcheck",
      "label": "our own monitoring account",
      "literal": true,
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
      "note": "",
      "source": ""
    }
  ],
  "proof": [
    {
      "text": "Mar 11 09:15:03 gate sshd[1]: Failed password for root from 203.0.113.77 port 22 ssh2",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "Mar 11 09:15:06 gate sshd[2]: Accepted publickey for deploy from 10.0.4.30",
      "expect": "should_not_match",
      "note": ""
    },
    {
      "text": "Mar 11 09:15:44 gate sshd[3]: Failed password for invalid user healthcheck from 10.0.0.9",
      "expect": "should_not_match",
      "note": ""
    },
    {
      "text": "Mar 11 09:15:44 gate sshd[4]: Failed password for admin from 10.0.4.9 port 22",
      "expect": "should_not_match",
      "note": "internal source \u2014 the Require rule drops this"
    }
  ],
  "sample": "ssh"
}
