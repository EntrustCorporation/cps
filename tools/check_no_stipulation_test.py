import unittest
from check_no_stipulation import check_no_stipulation, skip_frontmatter

markdown_content = """---
title: Test
subtitle: No stipulation
---

# Section 1

This is a paragraph with some **bold text** and *italic text*.

## Section 1.1

No stipulation.

# Section 2

# Section 2.1

# Section 2.1.1

# Section 3

Lorum ipsum.

# Section 3.1

# Section 3.2

Lorum ipsum.

# Section 3.3

# Section 4

"""

class TestCheckSkipFrontmatter(unittest.TestCase):
    def test_skip_frontmatter_with_markdown(self):
        result = skip_frontmatter(markdown_content)
        self.assertNotIn("---", result)

class TestCheckNoStipulation(unittest.TestCase):
    def test_check_no_stipulation_with_markdown(self):
        result = check_no_stipulation(markdown_content)
        expected_result = ["Section 'Section 2' is empty but does not contain 'No stipulation'.",
                           "Section 'Section 2.1' is empty but does not contain 'No stipulation'.",
                           "Section 'Section 2.1.1' is empty but does not contain 'No stipulation'.",
                           "Section 'Section 3.1' is empty but does not contain 'No stipulation'.",
                           "Section 'Section 3.3' is empty but does not contain 'No stipulation'.",
                           "Section 'Section 4' is empty but does not contain 'No stipulation'."]

        self.assertEqual(result, expected_result)


if __name__ == '__main__':
    unittest.main()
