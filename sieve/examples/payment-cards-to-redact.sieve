{
  "schema": 1,
  "name": "Payment cards to redact",
  "intent": "Find card numbers so they can be removed. Sweep with --redact.",
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
      "pattern": "\\b(?:4\\d{12}(?:\\d{3})?|5[1-5]\\d{14}|3[47]\\d{13}|6(?:011|5\\d{2})\\d{12}|3(?:0[0-5]|[68]\\d)\\d{11})\\b",
      "label": "payment card number",
      "literal": false,
      "whole_word": false,
      "capture": true,
      "capture_name": "pan",
      "ignore_case": null,
      "enabled": true,
      "repeat": {
        "mode": "once",
        "minimum": 1,
        "maximum": 1,
        "greedy": true
      },
      "note": "Does not run the Luhn check, so a fraction of hits are not valid card numbers. Sieve's scanner can redact these for you.",
      "source": "credit_card"
    },
    {
      "kind": "exclude",
      "pattern": "\\b0{12,19}\\b",
      "label": "all-zero test rows",
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
      "text": "2,Bram Okonkwo,b.okonkwo@example.co.uk,5500005555555559,refunded",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "4111111111111111",
      "expect": "should_match",
      "note": ""
    },
    {
      "text": "5,internal test,qa@example.com,0000000000000000,ignore",
      "expect": "should_not_match",
      "note": ""
    },
    {
      "text": "order id 1234567812345678",
      "expect": "should_not_match",
      "note": "right length, wrong prefix"
    }
  ],
  "sample": "pii"
}
