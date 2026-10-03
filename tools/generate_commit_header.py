"""Generate native commit metadata before the first ordered-build compilation."""
import calendar
from datetime import datetime
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
commit, date = subprocess.check_output(
    ['git', '-C', str(root), 'show', '--no-patch', '--format=%H%n%aI', 'HEAD'],
    text=True, encoding='utf-8').strip().splitlines()
if not re.fullmatch(r'[0-9a-f]{40}', commit):
    raise ValueError('Invalid Git commit metadata')
stamp = datetime.fromisoformat(date)
formatted = f'{stamp.year}-{calendar.month_abbr[stamp.month]}-{stamp.day} {stamp:%H:%M:%S%z}'
content = ('// This file is auto-generated, any edits may be overwritten\n'
           f'#define SOURCE_COMMIT_DATE "{formatted}"\n'
           f'#define SOURCE_COMMIT_HASH "{commit}"\n')
target = root / 'microscript/ILibDuktape_Commit.h'
if not target.exists() or target.read_text(encoding='utf-8') != content:
    target.write_text(content, encoding='utf-8')
