import unittest
from cabforum_links import replace_references, generate_document_pattern

document_input = """
Check SSL Baseline Requirements section 1.
TLS Baseline Requirements Section 1.2 if you like.
TLS BR section 1.2.3.
Code Signing Baseline Requirements section 2.
Code Signing BR section 3.6
TLS EV Guidelines
TLS EV Guidelines Section 4.5
"""

class TestCheckReplaceReferences(unittest.TestCase):
    def test_replace_references(self):
        document_pattern = generate_document_pattern()
        output = replace_references(document_input, document_pattern)

        expected_result = """
Check [SSL Baseline Requirements section 1](https://cabforum.org/working-groups/server/baseline-requirements/requirements/#section-1).
[TLS Baseline Requirements Section 1.2](https://cabforum.org/working-groups/server/baseline-requirements/requirements/#section-1.2) if you like.
[TLS BR section 1.2.3](https://cabforum.org/working-groups/server/baseline-requirements/requirements/#section-1.2.3).
[Code Signing Baseline Requirements section 2](https://cabforum.org/working-groups/code-signing/requirements/#section-2).
[Code Signing BR section 3.6](https://cabforum.org/working-groups/code-signing/requirements/#section-3.6)
TLS EV Guidelines
[TLS EV Guidelines Section 4.5](https://cabforum.org/working-groups/server/extended-validation/guidelines/#section-4.5)
"""
        self.maxDiff = 1000
        self.assertEqual(output, expected_result)


if __name__ == '__main__':
    unittest.main()
