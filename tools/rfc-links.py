import re
import sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <file>")
    sys.exit(1)

input_file = sys.argv[1]

rfc_pattern = re.compile(r'(?<!\[)(RFC\s?(\d+)(,?\s+[Ss]ection\s*([\d.]+))?)\b')

def replace_rfc_references(text):
    def replace_match(match):
        full_match = match.group(1)
        rfc_number = match.group(2)
        section = match.group(4) 

        url = f"https://www.rfc-editor.org/rfc/rfc{rfc_number}.html"
        if section:
            # Adjust the URL for the section
            url += f"#section-{section}"

        return f"[{full_match}]({url})"
    
    return rfc_pattern.sub(replace_match, text)

with open(input_file, 'r+', encoding='utf-8') as file:
    content = file.read()
    modified_content = replace_rfc_references(content)
    file.seek(0)
    file.write(modified_content)
    file.truncate()