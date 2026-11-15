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
POLICY = {"-ep", "-ex", "-executionpolicy"}
WINDOW = {"-w", "-wi", "-win", "-windowstyle"}
MAX_COMMAND = 16384
MAX_TOKENS = 256
MAX_ENCODED = 8192


def uid_zero_argument(event):
    """Exact supported useradd UID option; do not match UID 0001 or quoted comments."""
    command = event.get("command")
    if event.get("kind") != "process" or basename(event.get("process")) != "useradd":
        return False
    if not isinstance(command, str) or len(command) > MAX_COMMAND:
        return False
    try:
        args = shlex.split(command)
    except ValueError:
        return False
    if len(args) > MAX_TOKENS:
        return False
    index = 1
    value_options = {
        "-c",
        "--comment",
        "-d",
        "--home-dir",
        "-e",
        "--expiredate",
        "-f",
        "--inactive",
        "-g",
        "--gid",
        "-G",
        "--groups",
        "-k",
        "--skel",
        "-K",
        "--key",
        "-p",
        "--password",
        "-s",
        "--shell",
        "-R",
        "--root",
        "-P",
        "--prefix",
        "-b",
        "--base-dir",
    }
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        if arg in value_options:
            index += 2
            continue
        value = None
        if arg in {"-u", "--uid"} and index + 1 < len(args):
            value = args[index + 1]
        elif arg.startswith("--uid="):
            value = arg[6:]
        elif re.fullmatch(r"-u[0-9]+", arg):
            value = arg[2:]
        if value and re.fullmatch(r"0+", value):
            return True
        index += 2 if arg in {"-u", "--uid"} else 1
    return False


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
    result, current, quote = [], [], None
    for char in command:
        if char in "\"'":
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            else:
                current.append(char)
        elif char.isspace() and quote is None:
            if current:
                result.append("".join(current))
                current = []
                if len(result) >= MAX_TOKENS:
                    return None
        else:
            current.append(char)
    if quote:
        return None
    if current:
        result.append("".join(current))
    return result


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
    file_path, evasion = None, False
    index = 1 if not args[0].startswith("-") else 0
    while index < len(args):
        flag = args[index].casefold()
        value = args[index + 1] if index + 1 < len(args) else None
        if flag in FILE:
            if value and value != "-" and not value.startswith("-"):
                file_path = value
            break  # Everything following is a script parameter, not a PowerShell engine option.
        if flag in COMMAND:
            script = " ".join(args[index + 1 :])
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
        if flag in POLICY and value and value.casefold() == "bypass":
            evasion = True
        if flag in WINDOW and value and value.casefold() == "hidden":
            evasion = True
        index += 1
    if file_path:
        if basename(event.get("parent")) in OFFICE_NAMES and evasion:
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
