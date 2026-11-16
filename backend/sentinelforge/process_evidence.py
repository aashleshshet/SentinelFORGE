"""Bounded observation parsing, never a PowerShell interpreter or script executor.

Only engine options preceding -File/-Command are inspected as options. Original
filename, ancestry and script hashes are sensor claims, not a signature verdict.
"""

import base64
import binascii
import hashlib
import ntpath
import re
import shlex

POWERSHELL_NAMES = {"powershell.exe", "powershell", "pwsh.exe", "pwsh"}
OFFICE_NAMES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"}
ENCODED = {
    "-e",
    "-ec",
    "-en",
    "-enc",
    "-enco",
    "-encod",
    "-encode",
    "-encoded",
    "-encodedc",
    "-encodedco",
    "-encodedcom",
    "-encodedcomm",
    "-encodedcomma",
    "-encodedcomman",
    "-encodedcommand",
}
FILE = {"-f", "-fi", "-fil", "-file"}
COMMAND = {"-c", "-co", "-com", "-comm", "-comma", "-comman", "-command"}
POLICY = {"-ep"} | {"-executionpolicy"[:n] for n in range(3, 17)}
WINDOW = {"-windowstyle"[:n] for n in range(2, 13)}
# Supported engine options and their minimum prefixes from Microsoft's parser.
# Values must be consumed even when they look like another engine switch.
VALUE_OPTIONS = {
    "configurationname": "config",
    "configurationfile": "configurationfile",
    "custompipename": "cus",
    "inputformat": "inp",
    "outputformat": "o",
    "encodedarguments": "encodeda",
    "workingdirectory": "wo",
    "settingsfile": "settings",
}
SWITCH_OPTIONS = {
    "noexit": "noe",
    "noprofile": "nop",
    "nologo": "nol",
    "noninteractive": "noni",
    "interactive": "i",
    "login": "l",
    "sta": "sta",
    "mta": "mta",
    "noprofileloadtime": "noprofileloadtime",
}
MAX_COMMAND = 16384
MAX_TOKENS = 256
MAX_ENCODED = 8192


def uid_zero_argument(event):
    """Read the final supported useradd UID request without executing the command.

    useradd uses getopt_long: short options may be clustered, an option's value
    consumes the remainder of its token, and each -u replaces the preceding UID.
    Unsupported/invalid option syntax is unavailable evidence, not a zero UID.
    """
    command = event.get("command")
    executable = event.get("process")
    if (
        event.get("kind") != "process"
        or not isinstance(executable, str)
        or executable.rsplit("/", 1)[-1] != "useradd"
    ):
        return False
    if not isinstance(command, str) or len(command) > MAX_COMMAND:
        return False
    try:
        args = shlex.split(command)
    except ValueError:
        return False
    if not args or len(args) > MAX_TOKENS:
        return False
    index = 1
    value_options = {
        "base-dir": "b",
        "comment": "c",
        "home-dir": "d",
        "expiredate": "e",
        "inactive": "f",
        "gid": "g",
        "groups": "G",
        "skel": "k",
        "key": "K",
        "password": "p",
        "shell": "s",
        "root": "R",
        "prefix": "P",
        "uid": "u",
        "selinux-user": "Z",
        "selinux-range": "selinux-range",
    }
    flag_options = {
        "btrfs-subvolume-home",
        "badname",
        "no-log-init",
        "create-home",
        "no-create-home",
        "no-user-group",
        "non-unique",
        "system",
        "user-group",
        "add-subids-for-system",
    }
    short_values = set("bcdefgGkKpsRPuZ")
    short_flags = set("lmMNorUF")
    final_uid = None
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        if not arg.startswith("-") or arg == "-":
            # GNU getopt permits options after the account operand.
            index += 1
            continue
        selected, value = None, None
        if arg.startswith("--"):
            option, equals, attached = arg[2:].partition("=")
            if option in flag_options and not equals:
                index += 1
                continue
            if option not in value_options:
                return False
            selected = value_options[option]
            if equals:
                value = attached
            else:
                index += 1
                if index >= len(args):
                    return False
                value = args[index]
        else:
            for offset, option in enumerate(arg[1:], 1):
                if option in short_flags:
                    continue
                if option not in short_values:
                    # Includes -D (defaults only) and -h (help), neither creates an account.
                    return False
                selected = option
                value = arg[offset + 1 :]
                if not value:
                    index += 1
                    if index >= len(args):
                        return False
                    value = args[index]
                break
        if selected == "u":
            if not re.fullmatch(r"[0-9]+", value or ""):
                return False
            final_uid = value
        index += 1
    return final_uid is not None and re.fullmatch(r"0+", final_uid) is not None


def basename(value):
    return ntpath.basename(value.replace("/", "\\")).casefold() if isinstance(value, str) else ""


def path_key(value):
    # Lexical comparison only: no filesystem lookup, environment expansion or symlink claim.
    return ntpath.normpath(value.replace("/", "\\")).casefold() if isinstance(value, str) else ""


def tokens(command):
    """Simple single/double quoted argument forms with bounded linear scanning.

    Backticks, escaped embedded quotes and shell expansion are deliberately not
    interpreted. An unclosed quote makes the argument vector unavailable.
    """
    if not isinstance(command, str) or not command or len(command) > MAX_COMMAND:
        return None
    result, current, quote, started = [], [], None, False
    for char in command:
        if char in "\"'":
            started = True
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            else:
                current.append(char)
        elif char.isspace() and quote is None:
            if started:
                result.append("".join(current))
                current = []
                started = False
                if len(result) >= MAX_TOKENS:
                    return None
        else:
            current.append(char)
            started = True
    if quote:
        return None
    if started:
        result.append("".join(current))
    return result


def option_prefix(flag, options):
    key = flag.removeprefix("-")
    return flag.startswith("-") and any(
        full.startswith(key) and key.startswith(minimum) for full, minimum in options.items()
    )


def engine_flag(argument):
    """Canonicalize supported native option introducers, without expanding values."""
    argument = argument.strip().casefold()
    if argument.startswith("--"):
        return argument[1:]
    if argument.startswith("/"):
        return "-" + argument[1:]
    return argument


def scheduled_task_create(event):
    """Identify the schtasks operation, never a marker in its task/action values.

    This observes a creation request; it does not prove the task was registered.
    """
    if event.get("kind") != "process" or basename(event.get("process")) != "schtasks.exe":
        return False
    args = tokens(event.get("command"))
    if not args:
        return False
    index = 0 if args[0].startswith("/") else 1
    return index < len(args) and args[index].casefold() == "/create"


def process_evidence(event, script_indicator=None):
    result = {
        "powershell_encoded": False,
        "powershell_file_suspicious": False,
        "script_indicator_matched": False,
        "details": [],
    }
    fields = event.get("fields") or {}
    if event.get("kind") != "process" or not (
        basename(event.get("process")) in POWERSHELL_NAMES
        or basename(fields.get("original_file_name")) in POWERSHELL_NAMES
    ):
        return result
    args = tokens(event.get("command"))
    if not args:
        result["details"].append("PowerShell argument vector unavailable: missing, truncated or over bounds.")
        return result
    file_path, policy, window = None, None, None
    is_pwsh = any(
        basename(name) in {"pwsh", "pwsh.exe"}
        for name in (event.get("process"), fields.get("original_file_name"))
    )
    has_executable = (
        basename(args[0]) in POWERSHELL_NAMES
        or basename(args[0]) == basename(event.get("process"))
        or not args[0].startswith(("-", "/"))
    )
    index = 1 if has_executable else 0
    while index < len(args):
        flag = engine_flag(args[index])
        value = args[index + 1] if index + 1 < len(args) else None
        if flag in FILE:
            if value and value != "-" and not value.startswith("-"):
                file_path = value
            break  # Everything following is a script parameter, not a PowerShell engine option.
        if flag in COMMAND or flag in {"-commandwithargs", "-cwa"}:
            script = (value or "") if flag in {"-commandwithargs", "-cwa"} else " ".join(args[index + 1 :])
            if re.search(r"frombase64string|downloadstring\s*\(", script, re.I):
                result["powershell_encoded"] = True
                result["details"].append(
                    "Inline command contains a download/decode marker; intent is unverified."
                )
            break
        if flag in ENCODED:
            result["powershell_encoded"] = True
            if value is None or len(value) > MAX_ENCODED:
                result["details"].append(
                    "Encoded command marker; payload missing or exceeds 8192 characters."
                )
            else:
                try:
                    decoded = base64.b64decode(value, validate=True)
                    decoded.decode("utf-16-le", errors="strict")
                    result["details"].append(
                        f"Encoded UTF-16LE command observed ({len(decoded)} bytes; SHA256 {hashlib.sha256(decoded).hexdigest()}); never executed."
                    )
                except (ValueError, UnicodeError, binascii.Error):
                    result["details"].append(
                        "Encoded command marker with invalid or truncated Base64/UTF-16LE."
                    )
            break
        if flag in POLICY or flag in WINDOW:
            allowed = (
                {"allsigned", "bypass", "default", "remotesigned", "restricted", "undefined", "unrestricted"}
                if flag in POLICY
                else {"normal", "hidden", "minimized", "maximized"}
            )
            if not value or value.casefold() not in allowed:
                break
            if flag in POLICY:
                policy = value.casefold()
            else:
                window = value.casefold()
            index += 2
        elif option_prefix(flag, VALUE_OPTIONS) or flag in {"-if", "-of", "-ea", "-wd"}:
            if value is None:
                break
            if (
                option_prefix(flag, {"inputformat": "inp", "outputformat": "o"}) or flag in {"-if", "-of"}
            ) and value.casefold() not in {"text", "xml"}:
                break
            index += 2
        elif flag == "-version" and not is_pwsh:
            index += 2  # Windows PowerShell selects an engine version; pwsh prints and exits.
        elif option_prefix(flag, SWITCH_OPTIONS):
            index += 1
        else:
            # pwsh treats the first positional argument as its file. Unknown
            # switches/terminal modes cannot make later tokens engine options.
            if is_pwsh and flag and not flag.startswith("-"):
                file_path = args[index]
            break
    if file_path:
        if basename(event.get("parent")) in OFFICE_NAMES and (policy == "bypass" or window == "hidden"):
            result["powershell_file_suspicious"] = True
            result["details"].append(
                "PowerShell file execution with Office parent and explicit bypass/hidden option; behavior requires review."
            )
        # Only a provenance-checked indicator supplied by the context service can match.
        observed_hash = fields.get("script_sha256")
        if (
            script_indicator
            and path_key(fields.get("script_path")) == path_key(file_path)
            and isinstance(observed_hash, str)
            and re.fullmatch(r"[a-fA-F0-9]{64}", observed_hash)
            and observed_hash.casefold() == str(script_indicator.get("value", "")).casefold()
        ):
            result["powershell_file_suspicious"] = True
            result["script_indicator_matched"] = True
            result["details"].append(
                "Observed script path/hash matches an active operator-managed script indicator; collector attribution is required."
            )
    return result
