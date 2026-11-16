"""Bounded Linux command observations; no command or shell content is executed."""

import shlex

MAX_COMMAND = 16384
MAX_TOKENS = 256
SHELL_PATHS = {
    f"{directory}/{shell}" for directory in ("/bin", "/usr/bin") for shell in ("bash", "sh", "zsh")
}


def sudo_shell_command(event):
    """An accepted sudo policy log requests a supported root shell executable.

    The adapter's success outcome means permission was granted. It does not
    prove process completion, shell interactivity, or malicious intent. Linux
    paths are compared exactly and case-sensitively; arguments are never paths.
    """
    if (
        event.get("kind") != "privilege"
        or event.get("process") != "sudo"
        or event.get("outcome") != "success"
        or (event.get("fields") or {}).get("target_user") != "root"
    ):
        return False
    command = event.get("command")
    if not isinstance(command, str) or len(command) > MAX_COMMAND:
        return False
    try:
        args = shlex.split(command)
    except ValueError:
        return False
    return bool(args) and len(args) <= MAX_TOKENS and args[0] in SHELL_PATHS
