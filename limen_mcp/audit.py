from __future__ import annotations

import ipaddress
import json
import math
import posixpath
import re
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import parse_qsl, urlsplit

VERSION = "0.2.0"
MAX_BYTES = 1_048_576
SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_SECRET = re.compile(r"(?:^|[_-])(?:token|password|passwd|secret|api[_-]?key|access[_-]?key|private[_-]?key)$", re.I)
_PLACEHOLDER = re.compile(r"(?:\$\{(?:(?:env:)?[A-Za-z_][A-Za-z0-9_]*|input:[A-Za-z_][A-Za-z0-9_.-]*)\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)")
_NPM_PIN = re.compile(r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+@v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_PY_PIN = re.compile(r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc|post|dev)[0-9]+)?(?:\+[A-Za-z0-9.]+)?", re.I)
_UVX_PIN = re.compile(r"[A-Za-z0-9_.-]+@[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc|post|dev)[0-9]+)?", re.I)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    location: str
    message: str
    remediation: str


@dataclass
class Report:
    servers: int
    findings: list[Finding]
    errors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "summary": {"servers": self.servers, "findings": len(self.findings), "errors": len(self.errors)},
            "findings": [asdict(finding) for finding in self.findings],
            "errors": self.errors,
        }

    def exit_code(self, fail_on: str = "medium") -> int:
        if self.errors:
            return 2
        if fail_on == "never":
            return 0
        return int(any(SEVERITY[finding.severity] >= SEVERITY[fail_on] for finding in self.findings))


def _literal(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    candidate = re.sub(r"^(?:Bearer|Basic) +", "", value.strip(), flags=re.I)
    return not _PLACEHOLDER.fullmatch(candidate)


def _sensitive_key(key: str) -> bool:
    return bool(_SECRET.search(key)) or key.lower() in {"authorization", "proxy-authorization", "x-api-key", "apikey"}


def _basename(command: str) -> str:
    return PurePosixPath(command.replace("\\", "/")).name.lower().removesuffix(".exe")


def _loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower().rstrip(".") == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# Claves geminatae interpretationem ambiguam efficiunt.
def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("invalid number")
    return value


# Nuntii erroresque nullam materiam occultam repetunt.
def parse_config(data: bytes) -> Report:
    if len(data) > MAX_BYTES:
        return Report(0, [], ["Configuration exceeds the 1 MiB limit."])
    try:
        content = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_object, parse_float=_finite_float,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")))
    except (UnicodeError, ValueError, RecursionError):
        return Report(0, [], ["Configuration must be valid UTF-8 JSON with unique keys and finite numbers."])
    try:
        return audit_config(content)
    except RecursionError:
        return Report(0, [], ["Configuration nesting exceeds the supported limit."])


def audit_config(content: Any) -> Report:
    report = Report(0, [], [])
    if not isinstance(content, dict):
        report.errors.append("Configuration must be a JSON object.")
        return report
    roots = [key for key in ("mcpServers", "servers") if key in content]
    if not roots:
        report.errors.append("Configuration must contain an mcpServers or servers object.")
    for root in roots:
        entries = content[root]
        if not isinstance(entries, dict):
            report.errors.append(f"{root} must be an object.")
            continue
        # Nomina indicibus substituuntur, ne secreta pateant.
        for index, name in enumerate(sorted(entries), 1):
            location = f"{root}.server[{index}]"
            report.servers += 1
            _audit_server(entries[name], location, report)
    report.findings.sort(key=lambda finding: (finding.location, finding.rule_id, finding.message))
    return report


def _audit_server(server: Any, location: str, report: Report) -> None:
    def add(rule: str, severity: str, field: str, message: str, fix: str) -> None:
        report.findings.append(Finding(rule, severity, location + field, message, fix))

    if not isinstance(server, dict):
        report.errors.append(f"{location} must be an object.")
        return
    invalid = False
    for field in ("command", "url", "type", "transport"):
        if field in server and (not isinstance(server[field], str) or not server[field].strip()):
            report.errors.append(f"{location}.{field} must be a nonempty string.")
            invalid = True
    args = server.get("args", [])
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        report.errors.append(f"{location}.args must be an array of strings.")
        invalid = True
    for field in ("env", "headers"):
        values = server.get(field, {})
        if not isinstance(values, dict) or not all(isinstance(value, str) for value in values.values()):
            report.errors.append(f"{location}.{field} must be an object with string values.")
            invalid = True
            continue
        for index, key in enumerate(sorted(values), 1):
            if _sensitive_key(key) and _literal(values[key]):
                add("LM001", "high", f".{field}.entry[{index}]", "Literal value in a credential-bearing field; value and key withheld.",
                    "Remove the literal credential and use your client's documented secret input mechanism; rotate exposed credentials.")
    if invalid:
        return
    command, url = server.get("command"), server.get("url")
    transport = server.get("type", server.get("transport"))
    if "type" in server and "transport" in server and server["type"] != server["transport"]:
        report.errors.append(f"{location} has conflicting type and transport declarations.")
    if command and url:
        report.errors.append(f"{location} must not declare both command and url.")
    elif not command and not url:
        report.errors.append(f"{location} requires a command or url; this configuration shape is unsupported.")
    if transport not in {None, "stdio", "http", "sse", "streamable-http"}:
        add("LM002", "low", ".transport", "Unknown transport declaration; transport behavior cannot be verified.",
            "Check the client documentation and review this server manually.")
    elif (transport == "stdio" and url) or (transport in {"http", "sse", "streamable-http"} and command):
        report.errors.append(f"{location} transport does not match its command or url field.")
    if url:
        _audit_url(url, add, report, location)
    if command:
        executable = _basename(command)
        _audit_arg_secrets(args, add)
        if executable in {"sh", "bash", "zsh", "dash", "ksh", "fish"} and _shell_string_requested(executable, args):
            add("LM020", "medium", ".command", "A shell is asked to interpret a command string; the command body is not audited.",
                "Use an executable and separate argument array; manually review any required shell program.")
        if executable in {"powershell", "pwsh", "cmd"} and _shell_string_requested(executable, args):
            add("LM020", "medium", ".command", "A command interpreter is asked to interpret a command string; the command body is not audited.",
                "Use an executable and separate argument array; manually review any required shell program.")
        if executable in {"npx", "npx.cmd"}:
            _audit_npx(args, add)
        if executable == "uvx" or (executable == "uv" and args[:2] == ["tool", "run"]):
            _audit_uvx(args if executable == "uvx" else args[2:], add, 0 if executable == "uvx" else 2)
        if executable == "docker":
            _audit_docker(args, add)


def _audit_url(url: str, add: Any, report: Report, location: str) -> None:
    try:
        if any(ord(char) <= 32 or ord(char) == 127 for char in url):
            raise ValueError("invalid URL")
        parsed = urlsplit(url)
        if not parsed.hostname or not parsed.scheme or "\\" in parsed.netloc:
            raise ValueError("invalid URL")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("invalid URL")
    except ValueError:
        report.errors.append(f"{location}.url must be an absolute URL with a valid host and port.")
        return
    if parsed.scheme.lower() == "http" and not _loopback(parsed.hostname):
        add("LM010", "high", ".url", "Plaintext HTTP endpoint is outside a recognized loopback address.",
            "Use HTTPS with certificate verification or a separately secured local tunnel.")
    elif parsed.scheme.lower() not in {"http", "https"}:
        add("LM011", "low", ".url", "URL scheme is outside supported HTTP transports.",
            "Review this transport manually; this audit cannot assess its security.")
    if parsed.username is not None or parsed.password is not None:
        add("LM001", "high", ".url", "URL contains user information; credential material is withheld.",
            "Remove credentials from the URL and use your client's documented secret input mechanism.")
    if any(_sensitive_key(key) and _literal(value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)):
        add("LM001", "high", ".url.query", "URL query contains a literal credential-bearing parameter; key and value withheld.",
            "Remove credentials from URLs, where they can be retained in logs and history.")


def _audit_arg_secrets(args: list[str], add: Any) -> None:
    for index, arg in enumerate(args):
        if not arg.startswith("--"):
            continue
        key, separator, value = arg[2:].partition("=")
        if not _sensitive_key(key):
            continue
        if not separator and index + 1 < len(args):
            value = args[index + 1]
        if _literal(value) and not value.startswith("--"):
            add("LM001", "high", f".args[{index}]", "Command argument contains a literal credential-bearing option; value withheld.",
                "Use a supported secret input mechanism instead of placing credentials in process arguments.")


def _shell_string_requested(executable: str, args: list[str]) -> bool:
    # Optiones ante scriptum inspiciuntur; argumenta scripti non interpretantur.
    posix = executable not in {"powershell", "pwsh", "cmd"}
    value_options = {"-o", "-O", "+o", "+O", "--rcfile", "--init-file"} if posix else {
        "-executionpolicy", "-ep", "-inputformat", "-outputformat", "-version", "-windowstyle",
        "-workingdirectory", "-wd", "-settingsfile", "-configurationname", "-custompipename",
    }
    index = 0
    while index < len(args):
        arg = args[index]
        key = arg if posix else arg.lower()
        if arg == "--" or (not posix and key in {"-file", "-f"}):
            return False
        if posix and (re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", arg) or executable == "fish" and arg == "--command"):
            return True
        if not posix and key in {"-c", "-command", "-encodedcommand", "-e", "-ec", "-enc", "/c", "/k"}:
            return True
        if key in value_options:
            index += 2
            continue
        if not arg.startswith(("-", "+") if posix else (("/",) if executable == "cmd" else ("-",))):
            return False
        index += 1
    return False


def _audit_npx(args: list[str], add: Any) -> None:
    packages: list[tuple[int, str]] = []
    incomplete = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"--yes", "-y", "--no", "--no-install", "--quiet", "-q"}:
            index += 1
            continue
        if arg == "--":
            index += 1
            if not packages and index < len(args):
                packages.append((index, args[index]))
            break
        if arg in {"--package", "-p"}:
            if index + 1 >= len(args):
                _incomplete(add, "npx")
                return
            packages.append((index + 1, args[index + 1]))
            index += 2
            continue
        if arg.startswith("--package="):
            packages.append((index, arg.split("=", 1)[1]))
            index += 1
            continue
        if arg in {"-c", "--call"} or arg.startswith("--call="):
            add("LM020", "medium", f".args[{index}]", "npx is asked to interpret a shell command string; the command body is not audited.",
                "Use a reviewed executable with separate arguments; manually review any required shell program.")
            if arg in {"-c", "--call"} and index + 1 >= len(args):
                _incomplete(add, "npx")
            incomplete = True
            break
        if arg.startswith("-"):
            _incomplete(add, "npx")
            incomplete = True
            break
        if not packages:
            packages.append((index, arg))
        break
    if not packages and not incomplete:
        _incomplete(add, "npx")
    for index, package in packages:
        if not _NPM_PIN.fullmatch(package):
            add("LM030", "medium", f".args[{index}]", "npx package is not an exact registry version recognized by this audit.",
                "Pin the package to a reviewed exact version; separately verify publisher, lockfile, integrity, and updates.")


def _audit_uvx(args: list[str], add: Any, offset: int = 0) -> None:
    packages: list[tuple[int, str, bool]] = []
    index, source = 0, False
    target, incomplete = False, False
    while index < len(args):
        arg = args[index]
        if arg in {"--offline", "--no-cache", "--no-progress", "-q", "--quiet", "--isolated"}:
            index += 1
            continue
        if arg in {"--from", "--with"} or arg.startswith(("--from=", "--with=")):
            key, separator, value = arg.partition("=")
            if not separator:
                if index + 1 >= len(args):
                    _incomplete(add, "uvx")
                    return
                index += 1
                value = args[index]
            packages.append((index, value, True))
            source = source or key == "--from"
            index += 1
            continue
        if arg == "--":
            index += 1
            target = index < len(args)
            if not source and target:
                packages.append((index, args[index], False))
            break
        if arg.startswith("-"):
            _incomplete(add, "uvx")
            incomplete = True
            break
        target = True
        if not source:
            packages.append((index, arg, False))
        break
    if not target and not incomplete:
        _incomplete(add, "uvx")
    for index, package, requirement in packages:
        if not (_PY_PIN if requirement else _UVX_PIN).fullmatch(package):
            add("LM031", "medium", f".args[{index + offset}]", "uv tool package is not an exact version recognized by this audit.",
                "Pin the tool and extra requirements to reviewed exact versions; separately verify dependencies and artifacts.")


def _incomplete(add: Any, launcher: str) -> None:
    add("LM090", "low", ".args", f"{launcher} arguments include an unsupported or incomplete form; coverage is partial.",
        "Review launcher options manually and use a supported explicit argument form where possible.")


_DOCKER_VALUE_OPTIONS = {
    "--name", "--hostname", "-h", "--user", "-u", "--workdir", "-w", "--env", "-e", "--env-file",
    "--volume", "-v", "--mount", "--network", "--net", "--publish", "-p", "--expose", "--entrypoint",
    "--label", "-l", "--label-file", "--memory", "-m", "--cpus", "--cpu-shares", "--restart",
    "--security-opt", "--cap-add", "--cap-drop", "--device", "--pid", "--ipc", "--gpus",
    "--add-host", "--dns", "--pull", "--platform", "--tmpfs",
}
_DOCKER_BOOLEAN_OPTIONS = {"--rm", "--interactive", "-i", "--tty", "-t", "-it", "-ti", "--detach", "-d", "--read-only", "--init", "--privileged"}


# Post imaginis nomen argumenta ad programma internum pertinent.
def _audit_docker(args: list[str], add: Any) -> None:
    if not args or args[0] not in {"run", "create"}:
        _incomplete(add, "docker")
        return
    index = 1
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if not arg.startswith("-"):
            break
        key, separator, value = arg.partition("=")
        if key in _DOCKER_BOOLEAN_OPTIONS:
            if separator and value not in {"1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False"}:
                _incomplete(add, "docker")
                return
            if key == "--privileged" and (not separator or value in {"1", "t", "T", "TRUE", "true", "True"}):
                add("LM040", "critical", f".args[{index}]", "Docker privileged mode grants broad host capabilities.",
                    "Remove privileged mode and grant only the narrowly required capabilities and devices.")
            index += 1
            continue
        if key not in _DOCKER_VALUE_OPTIONS:
            if arg[:2] in {"-v", "-e", "-p", "-u", "-w", "-m"} and len(arg) > 2:
                key, value, separator = arg[:2], arg[2:], "="
            else:
                _incomplete(add, "docker")
                return
        if not separator:
            if index + 1 >= len(args):
                _incomplete(add, "docker")
                return
            index += 1
            value = args[index]
        field = f".args[{index}]"
        if key in {"--network", "--net"} and value.lower() == "host":
            add("LM041", "high", field, "Docker host networking removes the container network namespace boundary.",
                "Use an isolated network and publish only required ports on explicit interfaces.")
        if key in {"--pid", "--ipc"} and value.lower() == "host":
            add("LM042", "high", field, "Docker shares a host process or IPC namespace.",
                "Use private namespaces unless a reviewed requirement justifies host sharing.")
        if key == "--cap-add" and value.upper().removeprefix("CAP_") in {"ALL", "SYS_ADMIN", "SYS_PTRACE"}:
            add("LM043", "high", field, "Docker adds a broad or sensitive Linux capability.",
                "Drop unnecessary capabilities and keep only those justified by the server's function.")
        if key == "--security-opt" and value.lower() in {"seccomp=unconfined", "apparmor=unconfined", "label=disable"}:
            add("LM044", "high", field, "Docker disables a security confinement control.",
                "Use an appropriate confinement profile and review the server's specific needs.")
        if key in {"--volume", "-v", "--mount"}:
            _audit_mount(key, value, field, add)
        if key in {"--env", "-e"}:
            envkey, assigned, envvalue = value.partition("=")
            if not assigned:
                add("LM047", "low", field, "Docker explicitly forwards a host environment variable; its name is withheld.",
                    "Confirm the forwarded variable is necessary and does not expose unintended host secrets.")
            elif _sensitive_key(envkey) and _literal(envvalue):
                add("LM001", "high", field, "Docker environment option contains a literal credential-bearing value; key and value withheld.",
                    "Use a documented secret input mechanism and rotate exposed credentials.")
        index += 1

    if index >= len(args):
        _incomplete(add, "docker")
        return
    image = args[index]
    if "@" not in image:
        add("LM048", "medium", f".args[{index}]", "Docker image uses a mutable tag or an implicit default tag rather than a digest.",
            "Pin a reviewed image digest and plan updates; tags can be reassigned. A digest does not prove publisher trust or image safety.")
    elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:+-]*@sha256:[0-9a-f]{64}", image):
        add("LM049", "low", f".args[{index}]", "Docker image digest is malformed or outside the supported SHA-256 reference form.",
            "Review the reference manually and use a verified digest; reference syntax alone does not establish image trust.")


def _audit_mount(key: str, value: str, field: str, add: Any) -> None:
    if key == "--mount":
        options = dict(item.split("=", 1) if "=" in item else (item, "") for item in value.split(","))
        source = options.get("source", options.get("src", ""))
        if options.get("type") != "bind":
            return
    else:
        parts = value.split(":")
        if len(parts) < 2:
            return
        source = parts[0]
    normalized = posixpath.normpath(source.replace("\\", "/"))
    if normalized.endswith(("/docker.sock", "/podman.sock")) or "docker_engine" in normalized.lower():
        add("LM045", "critical", field, "Container receives a container-engine control socket; read-only filesystem mode does not prevent API commands.",
            "Remove the socket mount or use a narrowly authorized proxy with independently enforced access controls.")
    elif normalized == "/" or normalized in {"/etc", "/proc", "/sys", "/dev", "/home", "/root", "/var", "/var/run", "/run"}:
        add("LM046", "high", field, "Container receives a broad or sensitive host directory; mount contents are not inspected.",
            "Mount only the required subdirectory, prefer read-only access, and exclude credentials and host control paths.")
