import re
from src.patterns import PII_PATTERNS

MASK_CHAR = "*"

MASK_TEMPLATES = {
    "email": lambda v: v[:2] + MASK_CHAR * (v.index("@") - 2) + v[v.index("@"):],
    "credit_card": lambda v: MASK_CHAR * (len(v) - 4) + v[-4:],
    "ssn": lambda v: MASK_CHAR * 7 + v[-4:],
    "phone_us": lambda v: MASK_CHAR * (len(v) - 4) + v[-4:],
    "passport": lambda v: v[:2] + MASK_CHAR * (len(v) - 2),
}

DEFAULT_MASK = lambda v: MASK_CHAR * len(v)


def mask_value(pii_type, value):
    masker = MASK_TEMPLATES.get(pii_type, DEFAULT_MASK)
    return masker(value)


def mask_text(text):
    for pii_type, config in PII_PATTERNS.items():
        def replacer(match, t=pii_type):
            return mask_value(t, match.group())
        text = config["pattern"].sub(replacer, text)
    return text


def mask_findings(findings):
    for f in findings:
        f["masked_value"] = mask_value(f["type"], f["value"])
    return findings
