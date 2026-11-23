import re

PII_PATTERNS = {
    "email": {
        "pattern": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "sensitivity": "High",
    },
    "phone_us": {
        "pattern": re.compile(r'\b(\+1[\s.-]?)?(\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4}\b'),
        "sensitivity": "High",
    },
    "ssn": {
        "pattern": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "sensitivity": "Critical",
    },
    "credit_card": {
        "pattern": re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b'),
        "sensitivity": "Critical",
    },
    "ip_address": {
        "pattern": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b'),
        "sensitivity": "Medium",
    },
    "date_of_birth": {
        "pattern": re.compile(r'\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b'),
        "sensitivity": "High",
    },
    "passport": {
        "pattern": re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
        "sensitivity": "Critical",
    },
    "zip_code": {
        "pattern": re.compile(r'\b\d{5}(?:-\d{4})?\b'),
        "sensitivity": "Low",
    },
    "url": {
        "pattern": re.compile(r'https?://[^\s]+'),
        "sensitivity": "Low",
    },
}
