"""Defensive name reservation for the getdev CLI. getdev is not a Python package."""


def main() -> None:
    print(
        "getdev is a Rust CLI, not a Python package.\n"
        "This PyPI package only reserves the name so nobody malicious can claim it.\n"
        "\n"
        "Install the real tool:\n"
        "  curl -fsSL https://getdev.ai/install.sh | sh\n"
        "  npm i -g getdev\n"
        "  brew install getdev-ai/tap/getdev\n"
        "\n"
        "  site:    https://getdev.ai/cli\n"
        "  source:  https://github.com/getdev-ai/cli"
    )
