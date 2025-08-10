import datetime

def get_markdown_frontmatter(title: str, draft: bool = False) -> list[str]:
    """
    Returns a list of strings representing the markdown frontmatter block.
    The date is set to the current date in yyyy-mm-dd format.
    """
    frontmatter = [
        "---",
        f'title: "{title}"',
        f'date: {datetime.date.today().strftime("%Y-%m-%d")}',
        f'draft: {str(draft).lower()}',
        "---\n"
    ]
    return frontmatter
