"""
Refactors Terraform tag blocks to use local.common_tags.

Before:
  tags = {
    Name        = "foo"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }

After:
  tags = merge(local.common_tags, {
    Name = "foo"
  })
"""

import re
import sys
from pathlib import Path


def refactor_tags(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Detect "tags = {" — capture leading whitespace
        m = re.match(r'^(\s*)tags\s*=\s*\{\s*\n', line)
        if m:
            indent = m.group(1)
            out.append(f"{indent}tags = merge(local.common_tags, {{\n")
            i += 1
            # Collect body lines until closing "}"
            body = []
            while i < len(lines):
                inner = lines[i]
                # Skip the two common_tags lines
                if re.match(r'^\s*Environment\s*=\s*var\.environment\s*\n?$', inner):
                    i += 1
                    continue
                if re.match(r'^\s*ManagedBy\s*=\s*"Terraform"\s*\n?$', inner):
                    i += 1
                    continue
                # Closing brace at same indent level
                if re.match(rf'^{re.escape(indent)}\}}\s*\n?$', inner):
                    i += 1
                    break
                body.append(inner)
                i += 1
            # Remove trailing blank lines from body
            while body and body[-1].strip() == '':
                body.pop()
            out.extend(body)
            closing = indent + "})\n"
            out.append(closing)
        else:
            out.append(line)
            i += 1
    return ''.join(out)


def main():
    root = Path(__file__).parent.parent / "terraform"
    tf_files = list(root.rglob("*.tf"))

    changed = 0
    for path in sorted(tf_files):
        original = path.read_text(encoding="utf-8")
        updated = refactor_tags(original)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            print(f"  updated: {path.relative_to(root.parent)}")
            changed += 1

    print(f"\n{changed} file(s) updated.")


if __name__ == "__main__":
    main()
