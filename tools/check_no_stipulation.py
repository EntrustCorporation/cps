import sys
import logging
import mistune

logging.basicConfig(level=logging.INFO)

def skip_frontmatter(content):
    if content.startswith('---'):
        end = content.find('---', 3)
        if end != -1:
            return content[end+3:].strip()
    return content

def get_section_text(index, parsed_content, level):
    section_text = []
    for node in parsed_content[index+1:]:
        if node['type'] == 'heading' and node['attrs']['level'] <= level:
            break
        if 'children' in node:
            for child in node['children']:
                if 'raw' in child:
                    section_text.append(child['raw'])
    return ' '.join(section_text)

def check_no_stipulation(content):
    content = skip_frontmatter(content)
    markdown = mistune.create_markdown(renderer=None)
    parsed = markdown(content)

    errors = []

    # Traverse the parsed content to find sections
    for i, node in enumerate(parsed):
        if node['type'] == 'heading':
            section_title = node['children'][0]['raw']
            section_text = get_section_text(i, parsed, node['attrs']['level'])
            if section_text.strip() == '':
                errors.append(
                    f"Section '{section_title}' is empty but does not contain 'No stipulation'.")

    return errors

def main(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()

        errors = check_no_stipulation(content)
        if errors:
            for error in errors:
                logging.error(error)
            sys.exit(1)
        else:
            logging.info("All sections are correctly stipulated.")
    
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        logging.error(f"Usage: {sys.argv[0]} <file>")
        sys.exit(1)
    main(sys.argv[1])