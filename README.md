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


## New in 0.2: regression gates and SARIF

Create a separate, redacted baseline snapshot:

```sh
python3 -m limen_mcp examples/review.json \
  --write-baseline baseline.json --baseline-label workstation --fail-on never
python3 -m limen_mcp examples/review.json \
  --baseline baseline.json --baseline-label workstation --fail-on-new --format json
```

The second command exits `0` for unchanged findings. With `--fail-on-new`, added findings or severity increases meeting `--fail-on` exit `1`; resolved findings and severity decreases do not fail the gate. Without `--fail-on-new`, the original full-report threshold still applies. Input and baseline errors always exit `2`. Baseline operations require a matching public label; choose an opaque identifier, never a secret. Writing requires a new destination and never overwrites an existing baseline or configuration. Review changes before replacing a trusted baseline yourself.

**Identity limits:** server names and sensitive keys never enter a snapshot. Individual ordinal locations are not stable identities: renaming, adding, or removing a server can shift every later `server[n]`, and argument/entry positions can change. Snapshots therefore compare aggregate counts by rule, root and field kind, replacing ordinal indices with `[*]`. They do not pretend to match the same server across revisions. Moving one risky setting to a different server while fixing another can leave counts unchanged. For server-specific gates, audit separately scoped configurations under separate labels. A label is your assertion of scope, not a verification of configuration identity.

The optional JSON `comparison` object contains `added`, `resolved`, `unchanged`, and `severity_changed` arrays plus a `summary` of observation counts. Entries contain `rule_id`, `scope`, `severity`, and `count`; severity changes replace `severity` with `from` and `to`. Matching first cancels equal severity counts, then pairs remaining severity counts in ascending order. Such pairs describe aggregate severity shifts, not proven identity matches. Existing successful JSON retains `schema_version: 1` and all original fields.

A ready-made synthetic snapshot is included at `examples/review.baseline.json`, labeled `synthetic-example`.

Baseline snapshots are a distinct schema, not ordinary reports: `schema_version: 1`, `tool: "limen-mcp"`, `tool_version`, `label`, `comparison_scope: "aggregate-rule-scope"`, and `findings`. Each finding is a rule/scope/severity/count group. Version 0.2 snapshots only are accepted; unknown fields, unknown rules, duplicate keys/groups, invalid labels/counts, and incompatible versions fail closed. Input is capped at 1 MiB, 10,000 groups and 100,000 total observations. Message wording, names, values, original paths, hashes of secrets and timestamps are absent. Scope/risk counts still reveal configuration characteristics.

### SARIF 2.1.0

```sh
python3 -m limen_mcp examples/review.json --format json --fail-on never > limen-report.json
python3 -m limen_mcp examples/review.json --format sarif \
  --sarif-artifact limen-report.json --fail-on never > limen.sarif
```

SARIF groups findings with stable rule/scope/severity fingerprints, severity levels, rule help and execution status. It contains no source configuration names or values. Its default physical artifact is the public name `limen-report.json`, with a summary anchor on line 1, not an invented line inside the private configuration. `--sarif-artifact` accepts an explicitly public repository-relative report path. Never put a private path in that option. Produce that reviewed report in the checkout before uploading SARIF to a code-scanning service. The synthetic `%SRCROOT%` URI is `file:///source/`; consumers requiring an absolute checkout URI should map that base to their checkout. Upload permissions and service availability remain the user's responsibility. The exporter is schema-validated; live service ingestion has not been tested.

The report's fingerprint captures the public rule, aggregate scope and severity only; it has the same identity limitations as the baseline. No numeric vulnerability score is invented. An input failure produces valid SARIF with `executionSuccessful: false` and a generic diagnostic, still exiting `2`.

### Container image references

`LM048` reports mutable Docker tags, including version-looking tags and implicit `latest`, at medium severity. `LM049` reports malformed or unsupported digest forms at low severity. A syntactically complete SHA-256 image reference avoids those two findings; it does not establish image trust, publisher identity, signature validity or safe contents. Limen never pulls an image. Unknown launcher options stop inspection before guessing the image boundary. Try the wholly synthetic `examples/container-pins.json` fixture.

Format references: [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) and [code-scanning SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

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
