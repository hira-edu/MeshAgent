#!/usr/bin/env python3
"""
Codex Stop hook: enforce continuous work loop.

When Codex tries to stop, this hook checks whether there are still OPEN TODOs
in the regression matrix. If work remains, it blocks the stop and tells Codex
to continue with the next TODO.

See: https://developers.openai.com/codex/hooks
"""

import json
import os
import re
import sys


def count_open_todos(todo_path):
    """Count TODOs that are still OPEN in the TODO matrix."""
    if not os.path.exists(todo_path):
        return 0, 0
    with open(todo_path, "r", encoding="utf-8") as f:
        content = f.read()
    # Match table rows with | ... | OPEN | ...
    open_items = len(re.findall(r"\|\s*OPEN\s*\|", content))
    done_items = len(re.findall(r"\|\s*DONE\s*\|", content))
    return open_items, done_items


def get_next_open_todo(todo_path):
    """Get the ID and task description of the next OPEN P0 TODO."""
    if not os.path.exists(todo_path):
        return None, None
    with open(todo_path, "r", encoding="utf-8") as f:
        for line in f:
            # Match: | Phase | P0 | OPEN | TODO-NNN | description | ...
            m = re.match(
                r"\|\s*P\d+\s*\|\s*P0\s*\|\s*OPEN\s*\|\s*(TODO-\d+)\s*\|\s*([^|]+)",
                line,
            )
            if m:
                return m.group(1).strip(), m.group(2).strip()
    # No P0 open, try any priority
    with open(todo_path, "r", encoding="utf-8") as f:
        for line in f:
            m = re.match(
                r"\|\s*P\d+\s*\|\s*P\d+\s*\|\s*OPEN\s*\|\s*(TODO-\d+)\s*\|\s*([^|]+)",
                line,
            )
            if m:
                return m.group(1).strip(), m.group(2).strip()
    return None, None


def main():
    todo_path = os.path.join(
        os.environ.get("CODEX_WORKSPACE", "."),
        "docs",
        "testing",
        "20260331_REALIGNMENT_TODO_MATRIX.md",
    )

    open_count, done_count = count_open_todos(todo_path)
    total = open_count + done_count

    if open_count == 0:
        # All work is done -- allow the stop
        result = {"decision": "allow"}
        json.dump(result, sys.stdout)
        return

    # Work remains -- block the stop and continue
    todo_id, todo_desc = get_next_open_todo(todo_path)
    if todo_id:
        reason = (
            f"WORK REMAINING: {open_count}/{total} TODOs still OPEN. "
            f"Continue with {todo_id}: {todo_desc[:120]}. "
            f"Read docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md for full acceptance criteria. "
            f"Implement -> build -> test -> fix -> mark DONE -> move to next TODO."
        )
    else:
        reason = (
            f"WORK REMAINING: {open_count}/{total} TODOs still OPEN. "
            f"Read docs/testing/20260331_REALIGNMENT_TODO_MATRIX.md and continue "
            f"with the next OPEN item. Do not stop until all items are DONE."
        )

    result = {"decision": "block", "reason": reason}
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main()
