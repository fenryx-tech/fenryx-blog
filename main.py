#!/usr/bin/env python3
"""
Generate blog content from GitHub Issues
"""

import os
import requests
from datetime import datetime

# Configuration
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
REPO = os.environ.get("GITHUB_REPOSITORY", "")
BLOG_LABEL = "blog"

def get_issues():
    """Fetch all issues with blog label"""
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    url = f"https://api.github.com/repos/{REPO}/issues"
    params = {
        "labels": BLOG_LABEL,
        "state": "open",
        "per_page": 100,
        "sort": "created",
        "direction": "desc"
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code != 200:
        print(f"Error fetching issues: {response.status_code}")
        return []

    return response.json()

def generate_blog_list(issues):
    """Generate markdown list of blog posts"""
    if not issues:
        return "*目前沒有文章*"

    lines = []

    for issue in issues:
        title = issue["title"]
        url = issue["html_url"]
        created_at = datetime.strptime(issue["created_at"], "%Y-%m-%dT%H:%M:%SZ")
        date_str = created_at.strftime("%Y-%m-%d")

        # Get labels (excluding 'blog')
        labels = [l["name"] for l in issue["labels"] if l["name"] != BLOG_LABEL]
        label_str = " ".join([f"`{l}`" for l in labels]) if labels else ""

        line = f"- [{title}]({url}) - {date_str}"
        if label_str:
            line += f" {label_str}"

        lines.append(line)

    return "\n".join(lines)

def update_readme(content):
    """Update README.md with blog list"""
    readme_path = "README.md"

    with open(readme_path, "r", encoding="utf-8") as f:
        readme = f.read()

    # Find and replace content between markers
    start_marker = "<!-- gitblog start -->"
    end_marker = "<!-- gitblog end -->"

    start_idx = readme.find(start_marker)
    end_idx = readme.find(end_marker)

    if start_idx == -1 or end_idx == -1:
        print("Markers not found in README.md")
        return

    new_readme = (
        readme[:start_idx + len(start_marker)] +
        "\n\n" + content + "\n\n" +
        readme[end_idx:]
    )

    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(new_readme)

    print("README.md updated successfully")

def main():
    print(f"Fetching issues from {REPO}...")
    issues = get_issues()
    print(f"Found {len(issues)} blog posts")

    content = generate_blog_list(issues)
    update_readme(content)

if __name__ == "__main__":
    main()
