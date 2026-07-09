"""Defensive name reservation for the getdev CLI. getdev is not a Python package."""


def main() -> None:
    print(
        "getdev — verify, secure, and ship AI-generated code.\n"
        "\n"
        "getdev is a native CLI, not a Python package; this PyPI package only\n"
        "reserves the name so nobody malicious can claim it.\n"
        "\n"
        "Install the real tool:\n"
        "  curl -fsSL https://getdev.ai/install.sh | sh\n"
        "\n"
        "  site:    https://getdev.ai\n"
        "  source:  https://github.com/pzelenin/getdev-cli"
    )
