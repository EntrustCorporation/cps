import re
import sys

# Group related terms and their URLs together, ensuring more specific terms are listed first
url_groups = [
    (["TLS EV Guidelines", "SSL EV Guidelines"], "https://cabforum.org/working-groups/server/extended-validation/guidelines/"),
    (["TLS BR", "TLS Baseline Requirements", "SSL BR", "SSL Baseline Requirements"], "https://cabforum.org/working-groups/server/baseline-requirements/requirements/"),
    (["Code Signing Baseline Requirements", "Code Signing BR", "EV Code Signing"], "https://cabforum.org/working-groups/code-signing/requirements/"),
    # VMC Requirements
]

# Generate the document_pattern based on the url_groups
def generate_document_pattern():
    # Extract all terms and sort them by length (descending) to ensure more specific terms are matched first
    all_terms = sorted((term for terms, _ in url_groups for term in terms), key=len, reverse=True)
    # Escape special regex characters in terms
    escaped_terms = [re.escape(term) for term in all_terms]
    # Combine into a single regex pattern
    pattern = r'(?<!\[)((' + '|'.join(escaped_terms) + r'),?\s+[Ss]ection\s*([\d.]+))\b'
    return re.compile(pattern)

def get_url(text):
    for terms, url in url_groups:
        if any(term in text for term in terms):
            return url
    return None

def replace_references(text, document_pattern):
    def replace_match(match):
        full_match = match.group(1)
        section = match.group(3)
        url = get_url(full_match)

        if not url:
            return full_match

        if section:
            url += f"#section-{section}"

        return f"[{full_match}]({url})"

    return document_pattern.sub(replace_match, text)

def main(input_file):
    document_pattern = generate_document_pattern()

    try:
        with open(input_file, 'r+', encoding='utf-8') as file:
            content = file.read()
            modified_content = replace_references(content, document_pattern)
            file.seek(0)
            file.write(modified_content)
            file.truncate()
    except IOError as e:
        print(f"Error opening or reading file: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file>")
        sys.exit(1)
    main(sys.argv[1])