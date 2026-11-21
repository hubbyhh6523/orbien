# Strict offline configuration checks

Both binaries reject unknown configuration keys by default. Fix misspelled or
obsolete keys instead of relying on an ignored setting. There is no lenient
mode: a configuration for a newer binary may be refused by an older binary.
The existing camelCase and snake_case aliases are preserved; prefer camelCase
for ordinary settings and snake_case for token policy settings, matching the
current serialized representation.

```sh
orbien-server --check-config -c conf/orbien-server.toml
orbien --check-config -c conf/orbien.toml
```

The server check requires an explicit file. The client also supports its usual
config-path discovery. A successful check prints `configuration OK` and exits
with status 0. Invalid files, absent environment variables, invalid access
policies, unreadable/invalid TLS files and invalid plugin settings exit with
status 1. Command-line usage errors exit with status 2. Warnings do not change
the exit status.

The CLI loads the file through the startup loader, expands `{{env.NAME}}` and
`{{env.NAME:default}}`, resolves the paths handled by that loader, completes
defaults, and validates the candidate. Server checks construct the access
policy and TLS/QUIC crypto configuration. Client checks construct the same TLS
options and tunnel manager/plugins used at startup. These constructors do not
start background tasks. Configured TLS files must really exist; checking a
full example as shipped therefore requires supplying its example certificates.
The existing TOFU-store path interpretation is unchanged.

The check path creates no Tokio runtime, does not start the service, resolve
DNS, connect to any host, bind a port, perform a TLS handshake, or write a
TOFU fingerprint. An absent TOFU store is allowed: it would only be created
on a real first connection. Checks do not establish peer identity, certificate
acceptance by a remote peer, port availability, or network reachability.

Warnings cover unverified server identity (neither CA nor TOFU), disabled or
optional TLS, absent client CA, empty tokens, effective unrestricted token
policy dimensions, placeholder secrets and disabled dashboard authentication.
Warnings identify policy indexes/configuration fields, not token/password
values. Defaults and policy interpretation are not changed by the warnings.

Dashboard reload uses the same server loader and offline preflight. Only after
the entire candidate passes does it replace the access-policy Arc under its
write lock. Parse, environment, semantic, CIDR and TLS errors return an API
body with code 422 and an empty changed list, without replacing the policy or
modifying the startup configuration. The existing API keeps HTTP status 200
for these JSON-level errors. Missing config-path selection still returns body
code 400. This does not extend reload into a full listener/TLS/dashboard hot
restart: successful reload retains the existing access-policy-only scope.

CI runs `python3 scripts/check-configs.py --bin-dir target/debug` after building
both binaries. The script recursively discovers every TOML in `conf/` and
`docker/conf/`, copies those trees into a temporary directory, supplies ephemeral
OpenSSL-generated test certificates, and compares configuration bytes before
and after invoking the real binaries. No shipped certificate or real secret
is added to the repository. New example names must have an explicit role in
the script; unclassified samples fail rather than being silently skipped.

Every TOML under `tests/config/bad/{server,client}` must exit with exactly 1 and
contain the expected error reason recorded in its first comment. Panics,
unknown CLI options, missing binaries and timeouts are not accepted as negative
successes. Additional CLI cases check environment expansion, an occupied TCP
listener and UDP ports, absence of a connection to a reachable local peer,
non-resolvable hosts for every transport, and absence of TOFU writes. Each CLI
invocation has a 10-second timeout; certificate generation has a 30-second
limit. Python 3.11+ and OpenSSL are required for this script.
