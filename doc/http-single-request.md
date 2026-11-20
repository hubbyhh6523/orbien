# Single-request HTTP forwarding (issue #18)

Review base: `9c2f638e1b2b4f8281e4530383ba4bba3befea22`.

## Contract

For ordinary HTTP, each visitor connection forwards exactly one framed request.
The gateway and tls-term replace Connection with `close` on both sides. A later
HTTP request must use a new visitor connection and therefore repeats routing,
Basic Auth (where the gateway has such a rule), and all header rewrites. This is
not same-connection per-request rerouting. Pipelined bytes are discarded; they
are never sent to a second backend or interpreted as a continuation of body.

Both pre-read bytes and bytes arriving later use the same body limiter. A
request with neither Content-Length nor Transfer-Encoding has no body; a
Content-Length request copies exactly that many bytes. Only the `chunked`
transfer coding is accepted. Chunked payload content is unchanged, but chunk
extensions are validated and removed and sizes are serialized canonically.
Trailers are bounded, validated, and discarded, not merged into the head. Their
Trailer declaration is removed. Apps relying on trailers need an explicitly
reviewed trailer policy before using this mode.

Header input accepts uniform CRLF or LF-only, as in the preceding patch. Output
heads use CRLF. Chunk framing itself requires CRLF. Ambiguous CL/TE, duplicate
length fields, unsupported TE, Upgrade, and Connection options other than
close/keep-alive fail closed. WebSocket/101 Upgrade is not supported in this
single-request path; this is an intentional compatibility change.

Upload and download run concurrently. Interim 1xx responses are flushed, with
an upper bound of 16 responses. HEAD/204/304 responses end after the head;
Content-Length and chunked responses end at their framing boundary, without
waiting for a backend that ignores Connection: close to disconnect. A response
with no declared length is copied until backend EOF. A complete early final
response cancels any remaining upload. An incomplete request body, invalid
chunk/trailer, response truncation, or exchange timeout closes the streams.
Already-streamed body prefixes cannot be rolled back at the backend.

The shared helper has a default 300-second absolute exchange timeout, not an
idle timeout. It is configurable by the Rust ForwardLimits parameter, not yet
through TOML. Long uploads and SSE streams exceeding this total deadline are
not supported by these default call sites. Timeout/config integration should
be reviewed before production deployment. Initial-head/TLS handshake deadlines
and concurrency admission remain separate work (#13).

## CONNECT exception

CONNECT retains the legacy raw relay behavior after the existing route/auth
and header rewrite stages. Buffered bytes and subsequent bytes pass through;
there is no single-request body boundary or 300-second exchange deadline on
this exception. The helper does NOT synthesize a 200 response and does NOT
turn the gateway into a new general-purpose forward proxy. Existing Host,
route, auth, and backend support requirements remain. Successful CONNECT can
carry arbitrary application data, including HTTP; do not confuse that with a
pipeline bypass on an ordinary GET/POST connection.

## Tests

```sh
cargo fmt --all -- --check
cargo test -p orbien-core --test http_forward_tcp
cargo test -p orbien-core net::http_forward
cargo test -p orbien-core --test http_head_rewrite
cargo test -p orbien-client
cargo build -p orbien-server -p orbien-client
python3 tests/e2e_http_single_request.py \
  --server target/debug/orbien-server --client target/debug/orbien
```

Python process tests use the standard library and openssl CLI, real server and
client binaries, real localhost TCP sockets, and a verified test certificate.
One test traverses HTTP gateway -> data connection -> client -> backend. The
other traverses HTTPS SNI gateway -> data connection -> tls-term -> backend.
Each runs four cases (two GETs, binary CL POST, binary chunked POST, changed
Host/path/credentials), asserting exactly one independently decoded backend
request with the first target/body/credentials. The backend deliberately does
not honor Connection: close and checks for late bytes as well. New HTTP
connections with bad credentials/unknown Host must return 401/404 without a
backend connection. tls-term has no Basic Auth policy of its own; no such
policy is claimed or added by these tests.

Rust tests also use real TCP, covering both prefetched and streamed body /
pipeline bytes, 100 Continue, and CONNECT passthrough. Unit tests cover
truncation, chunk extensions, HEAD/204/304, and response chunk boundaries.

The default server main declares `mod tunnel`, not `mod proxy`. Both source
call sites are patched, but the real process tests exercise the currently
built tunnel gateway, not an unbuilt legacy vhost listener. No successful
legacy-vhost runtime test is claimed. Enabling/building that legacy module is
not part of this patch.

No dependency changes, GitHub writes, or CI workflow changes are included.
Counters on failed exchanges still follow the Result-returning helper's
limitation: bytes sent before an error are not returned to the metrics caller
(#5). Passing source/patch checks does not mean Rust or production E2E tests
have passed.
