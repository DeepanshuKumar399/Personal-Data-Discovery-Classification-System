import unittest
from src.patterns import PII_PATTERNS


class TestPatterns(unittest.TestCase):

    def _match(self, pii_type, text):
        return PII_PATTERNS[pii_type]["pattern"].search(text)

    def test_email(self):
        self.assertIsNotNone(self._match("email", "contact: user@example.com"))
        self.assertIsNone(self._match("email", "not-an-email"))

    def test_ssn(self):
        self.assertIsNotNone(self._match("ssn", "SSN: 123-45-6789"))
        self.assertIsNone(self._match("ssn", "12345678"))

    def test_credit_card(self):
        self.assertIsNotNone(self._match("credit_card", "Card: 4111111111111111"))
        self.assertIsNone(self._match("credit_card", "1234"))

    def test_phone_us(self):
        self.assertIsNotNone(self._match("phone_us", "Call 555-867-5309"))

    def test_ip_address(self):
        self.assertIsNotNone(self._match("ip_address", "IP: 192.168.1.1"))
        self.assertIsNone(self._match("ip_address", "999.999.999.999"))

    def test_date_of_birth(self):
        self.assertIsNotNone(self._match("date_of_birth", "DOB: 01/15/1990"))

    def test_zip_code(self):
        self.assertIsNotNone(self._match("zip_code", "ZIP: 90210"))

    def test_passport(self):
        self.assertIsNotNone(self._match("passport", "Passport: AB1234567"))


if __name__ == "__main__":
    unittest.main()
