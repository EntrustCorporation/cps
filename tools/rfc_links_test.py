import unittest
from rfc_links import replace_rfc_references

document_input = """
Check RFC 1234.
Or RFC 1234 specifically RFC 1234, Section 1.2.
Maybe RFC 1234 section 5.
"""

class TestCheckReplaceRFCReferences(unittest.TestCase):
    def test_replace_rfc_references(self):
        output = replace_rfc_references(document_input)

        expected_result = """
Check [RFC 1234](https://www.rfc-editor.org/rfc/rfc1234.html).
Or [RFC 1234](https://www.rfc-editor.org/rfc/rfc1234.html) specifically [RFC 1234, Section 1.2](https://www.rfc-editor.org/rfc/rfc1234.html#section-1.2).
Maybe [RFC 1234 section 5](https://www.rfc-editor.org/rfc/rfc1234.html#section-5).
"""
        self.assertEqual(output, expected_result)


if __name__ == '__main__':
    unittest.main()
