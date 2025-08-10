def extract_text_from_element(element):
    """
    Recursively extracts and concatenates text from an XML element and its children.
    """
    text = element.text or ""
    for child in element:
        text += extract_text_from_element(child)
        text += child.tail or ""
    return text

def extract_description_with_html(element, ns):
    """
    Extracts and formats the text from an XML element that may contain HTML tags.
    """
    if element is None:
        return ""

    if not list(element):  # If the element has no children, return its text directly
        return element.text or ""

    # Process elements with children (like those with HTML content)
    text_parts = [element.text or ""]
    for child in element:
        if child.tag == '{http://www.w3.org/1999/xhtml}p':
            text_parts.append(extract_text_from_element(child))
            text_parts.append("\n")  # Adding a newline for paragraph break
        elif child.tag in ['{http://www.w3.org/1999/xhtml}ul', '{http://www.w3.org/1999/xhtml}li']:
            text_parts.append(extract_text_from_element(child))  # Keeping list item content

    return " ".join(text_parts).strip()
