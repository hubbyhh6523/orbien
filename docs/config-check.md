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

Token policies (`[[auth.token_policies]]`) restrict what each token may do.
`allowed_domains` applies to `http` and `https` tunnels: exact domain names
and `*.suffix` patterns, matched against the final expanded domain list, so
subdomain prefixes under `rootDomain` are covered too. A policy with an empty
`allowed_domains` allows only names under `rootDomain`; with no policies
configured at all, a full domain outside `rootDomain` is refused. An invalid
pattern (bare `*`, `*.`, illegal characters), a duplicate token, or a token
that is not listed while policies exist, fails the check and the startup.
Rejected registrations, resume attempts and data connections are logged with
the token id (first 16 chars of the SHA-256 hex) and the reason, never the
raw token; client-supplied text in log lines is sanitized and truncated.

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

## [limits]

The server `[limits]` table bounds what an unauthenticated connection can
consume before it logs in, and what idle joined connections may hold. All
keys are optional; the defaults below apply when the table is absent. Unknown
keys are rejected. A commented example with these defaults lives in
`conf/orbien-server-full.toml`.

- `preLoginTimeoutSecs` (default 10, must be > 0): deadline from accept to
  login. It covers the peek, the WebSocket upgrade and the TLS handshake,
  the first control message, and a yamux session or QUIC connection that
  never logs in. A peer that connects and sends nothing, or a byte at a
  time, is cut off at this deadline.
- `idleTimeoutSecs` (default 3600, 0 disables): a joined TCP/HTTPS
  connection or HTTP exchange with no bytes flowing for this long is
  aborted. The HTTP 300 s absolute exchange deadline is unchanged; the
  two run together and whichever fires first wins. Setting this to 0
  produces a risk warning in `--check-config` (idle connections are then
  unbounded).
- `firstMessageMaxBytes` (default 4096, must be > 0): the first control
  message (Login or NewDataConn) may not exceed this; the length is
  checked before the body is allocated, so a peer that declares a huge
  body and stalls is rejected from the header alone. Later messages use
  per-type limits: 1 KiB for Ping/Pong/KickOut/CloseTunnel/NewTunnelResp/
  LoginResp/StartDataConn/ReqDataConn/P2p*, 4 KiB for Login/NewDataConn,
  64 KiB for NewTunnel, 256 KiB for UdpPacket.
- `preLoginMaxConns` (default 512, must be > 0) and
  `preLoginMaxConnsPerIp` (default 32, must be > 0): how many
  not-yet-logged-in connections the server holds, globally and per client
  IP. Over the cap the connection is closed at once. A successful login
  releases the slot.
- `maxWaitingVisitorsPerTunnel` (default 32, must be > 0): visitors
  waiting for a data connection on one tunnel. Over the cap a visitor is
  refused immediately instead of queueing up to 10 s.
- `maxOutstandingDataConns` (default 8, may be 0): how many `ReqDataConn`
  requests may be outstanding per session above `poolCount`. The client
  likewise ignores `ReqDataConn` above `poolCount + 8`.
- `poolIdleTtlSecs` (default 300, must be > 0): a pooled data stream idle
  longer than this is dropped instead of being handed to a visitor.

QUIC defaults changed with the same release: `maxIncomingStreams` 1000
(was 100000), stream receive window 1 MiB (was 32 MiB), connection receive
window 8 MiB (was 64 MiB), send window 8 MiB (was 64 MiB). The old values
are still reachable through `[transport.quic]`. QUIC address validation
(Retry) is not enabled: quinn 0.11 exposes no public switch for it.

Supervisor behavior change: an accept failure (for example EMFILE) no
longer exits the server. The listener logs at most once per 10 s, backs
off exponentially (10 ms, doubling, capped at 1 s) and retries, and a
listener that exits on its own is now an error instead of a silent
success. Deployments that relied on the process exiting to trigger a
restart should keep their restart policy anyway (the process still exits
on a genuinely fatal error), but they must not assume a listener failure
restarts it.

Rejections are counted per reason in the server snapshot
(`limit_rejections`): `pre_login_timeout`, `first_message_too_large`,
`pre_login_cap`, `waiting_visitors`, `idle_timeout`,
`unexpected_message`. A session that sends more than 10 unknown control
messages is disconnected; the accept-error, ignored-message and
P2P-no-handler logs are each rate-limited to one line per 10 s.
