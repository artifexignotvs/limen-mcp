<div align="center">

# LIMEN

**Know what your agent is allowed to launch.**

A local audit of MCP server configuration risk. No server execution. No network calls. No runtime dependencies.

`Python 3.10+` · `MIT` · `Text + JSON` · `CI exit codes`

</div>

MCP configurations are small files with large consequences: a package fetched at launch, a credential in an argument, a container holding the host's control socket. Limen makes those settings visible before you enable the server.

It reads the configuration you provide and reports specific reviewable risks. It does **not** run servers, fetch packages, probe endpoints, expand environment variables, or enforce permissions.

## Try it in 30 seconds

From a local checkout, Python is the only requirement:

```sh
python3 -m limen_mcp examples/review.json
```

The review fixture deliberately contains risky settings and exits `1`. Nothing in it is executed. Sample output, abbreviated:

```text
Limen MCP | 3 server(s) | 5 finding(s) | 0 input error(s)
CRITICAL LM040 mcpServers.server[1].args[2]
         Docker privileged mode grants broad host capabilities.
HIGH     LM041 mcpServers.server[1].args[3]
         Docker host networking removes the container network namespace boundary.
CRITICAL LM045 mcpServers.server[1].args[5]
         Container receives a container-engine control socket; read-only filesystem mode does not prevent API commands.
MEDIUM   LM030 mcpServers.server[2].args[1]
         npx package is not an exact registry version recognized by this audit.
HIGH     LM010 mcpServers.server[3].url
         Plaintext HTTP endpoint is outside a recognized loopback address.
```

The full report also gives a concrete remediation for each finding.

```sh
python3 -m limen_mcp examples/local.json
python3 -m limen_mcp path/to/config.json --format json
python3 -m limen_mcp path/to/config.json --fail-on high
python3 -m limen_mcp - --format json < path/to/config.json
```

Optional installation from your reviewed checkout:

```sh
python3 -m pip install .
limen-mcp path/to/config.json
```

Installation uses the standard packaging build tool; running from the checkout needs no installation.

## What it checks

| Rule | Severity | Evidence inspected |
| --- | --- | --- |
| `LM001` | High | Literal credential-bearing `env` or `headers` fields, URL user information or sensitive query parameters, named credential arguments, Docker environment values |
| `LM002` | Low | Unknown declared transport |
| `LM010` | High | HTTP endpoint outside a recognized loopback address |
| `LM011` | Low | URL scheme outside HTTP and HTTPS |
| `LM020` | Medium | Shell, command interpreter, or `npx` with an explicit command-string option |
| `LM030` | Medium | `npx` package without a recognized exact registry version |
| `LM031` | Medium | `uvx` or `uv tool run` requirement without a recognized exact version |
| `LM040` | Critical | Docker `--privileged`, including supported true-value aliases |
| `LM041` | High | Docker host networking |
| `LM042` | High | Docker host PID or IPC namespace |
| `LM043` | High | Docker `ALL`, `SYS_ADMIN`, or `SYS_PTRACE` capability, including `CAP_` prefixes |
| `LM044` | High | Docker explicitly disables a confinement profile |
| `LM045` | Critical | Container-engine socket mount, including a read-only mount |
| `LM046` | High | Broad or sensitive POSIX host directory mount |
| `LM047` | Low | Docker explicitly forwards a host environment variable using `-e NAME` |
| `LM090` | Low | Incomplete or unsupported launcher arguments; partial inspection |

Findings identify configuration evidence, not successful exploitation. A private network HTTP endpoint still receives `LM010`; private addressing does not provide transport encryption.

## Supported configuration

Limen accepts JSON with an `mcpServers` object, a `servers` object, or both. Each server uses a `command` with an optional string `args` array, or an absolute `url`. Optional `env` and `headers` maps must contain string values. Supported explicit `type` or `transport` values are `stdio`, `http`, `sse`, and `streamable-http`.

```json
{
  "mcpServers": {
    "local-server": {
      "command": "python3",
      "args": ["-m", "your_local_server"],
      "env": {"SERVICE_TOKEN": "${SERVICE_TOKEN}"}
    }
  }
}
```

Placeholder syntax above is illustrative. Limen recognizes standalone `${NAME}`, `${env:NAME}`, `${input:name}`, `$NAME`, and `%NAME%` placeholders, including an optional authorization scheme prefix, and excludes them from literal-credential findings. Names use letters, digits, and underscores; input names may also include dots and hyphens. Expressions with literal defaults, such as `${TOKEN:-literal}`, are treated as literal credential material. It does **not** resolve placeholders or promise that a particular client supports their syntax.

Malformed JSON, duplicate keys, nonfinite numbers, unsupported core field shapes, conflicting transports, invalid URL authorities or raw URL whitespace/control characters, and unreadable files produce input errors. Unknown extension fields are ignored. JSON comments and trailing commas are not supported. Inputs are limited to 1 MiB.

## Reports you can share with less risk

Reports never echo configuration values, server names, dynamic credential keys, file paths, or parser exception details. Servers receive ordinal identifiers after their names are sorted. `server[1]` means the first server in that lexical ordering; argument offsets use zero-based indexing. Environment and header entries also use sorted, one-based ordinals.

This makes locations deterministic without retaining the original names. The report still reveals which categories of risky settings exist; review it before sharing. Limen does not sanitize your original configuration file or unrelated terminal output.

JSON reports have `schema_version`, `summary`, `findings`, and `errors` fields. Every finding includes a stable `rule_id`, `severity`, `location`, `message`, and `remediation`. Messages may evolve; automation should use IDs and severity.

## Use it as a CI check

```sh
python3 -m limen_mcp path/to/config.json --format json --fail-on high > audit.json
```

| Exit | Meaning |
| --- | --- |
| `0` | No input errors and no findings at or above the selected threshold |
| `1` | Findings at or above the selected threshold |
| `2` | Invalid or unreadable input, or invalid CLI invocation |

The default threshold is `medium`. `--fail-on low` also fails on incomplete launcher coverage. `--fail-on never` reports findings without failing for them; input errors still exit `2`. Invalid CLI invocation is handled by the argument parser and is not a JSON audit report.

## Deliberate limits

- **Audit only.** Limen is not a sandbox, a runtime firewall, a permission broker, or a test of model behavior. A clean report is not a security guarantee.
- **Local evidence only.** It cannot inspect server code, downloaded packages, image contents, DNS resolution, certificates, actual bindings, inherited client environment, effective permissions, or the network path.
- **Conservative launch parsing.** It recognizes direct `npx`, `uvx`, `uv tool run`, and `docker run` / `docker create` commands. Wrappers, shell bodies, other container runtimes, and launcher options outside the supported parser need manual review. Docker inspection stops at an unknown option to avoid confusing an option value with the image or its command.
- **Version pins are only one control.** Exact top-level package versions do not prove trust, artifact integrity, transitive dependency pinning, or reproducible installation. Local paths and non-registry sources are reported as unrecognized pins.
- **Credential names are heuristics.** A value in a key ending with token, password, secret, API key, or a related supported label receives a finding; arbitrary secret values under unrelated names may be missed. Empty values and recognized placeholders are skipped. Limen never verifies credentials.
- **Mount checks are narrow.** They recognize literal POSIX paths for broad directories and familiar container-engine socket names. They do not resolve symlinks, expand variables, inspect file contents, or reliably interpret Windows drive-letter mounts. A narrow directory can still contain sensitive files.
- **Client behavior varies.** A disabled server is still audited. Unknown extension keys are not validated, and no claim is made about a client's default environment inheritance or approval behavior.

## Development

```sh
python3 -m unittest discover -s tests -v
```

Tests cover redaction through successful and failing reports, JSON validation, launcher boundaries, exact package pins, transport distinctions, Docker privileges, deterministic output, and CLI exit behavior. All fixtures are synthetic. Source annotations use Latin; user-facing diagnostics use English.

Contributions should include a reproducible synthetic configuration, a precise explanation of the risk, and a regression test. Prefer a clearly reported coverage limitation over a confident but ambiguous interpretation.

## Security reports

Do not paste real credentials or private configuration into an issue. Use a synthetic reproducer with the same structure. For sensitive flaws, use the repository's private vulnerability reporting feature when it is enabled; otherwise avoid posting exploit details publicly.

MIT licensed. See [LICENSE](LICENSE).
