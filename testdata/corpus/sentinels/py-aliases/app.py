"""A5 regression sentinel: every import below has a PyPI distribution name
that differs from its Python import name (`rules/real/py-import-aliases.json`).
Deliberately plain `import <name>` statements with no attribute access — the
alias table's job is proving `deps::build_graph` classifies these as
resolved (not `real/phantom-import`) purely from the import graph; member
access against an installed surface is a separate concern already covered
by other fixtures.
"""

import yaml
import PIL
import dotenv
