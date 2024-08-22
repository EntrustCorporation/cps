import io
import unittest
from check_sections import check_markdown_headers

document_input = io.StringIO("""---
title: Test
subtitle: Sections
---

# 1 Introduction

This is a paragraph with some **bold text** and *italic text*.

## 1.1 Background

# 2 Not defined

## 2.1 Not defined

### 2.2 Incorrect header level

""")

sections = {
    "1": "Introduction",
    "1.1": "Background",
    "2.2": "Incorrect header level"
}

class TestCheckMarkdownHeaders(unittest.TestCase):
    def test_check_markdown_headers(self):
        output = io.StringIO()
        check_markdown_headers(document_input, sections, output)

        expected_result = """= Section 1 title matches: introduction
= Section 1.1 title matches: background
+ Section 2 (not defined) not found in sections dictionary
+ Section 2.1 (not defined) not found in sections dictionary
! Section 2.2 (level 2) does not match header level 3
= Section 2.2 title matches: incorrect header level
"""
        self.assertEqual(output.getvalue(), expected_result)


if __name__ == '__main__':
    unittest.main()
