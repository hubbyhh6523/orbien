#!/usr/bin/env python3
"""Exercise real offline CLI checks. Requires Python >=3.11 and openssl."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TIMEOUT = 10


def invoke(command, cwd, expected_code, reason=None):
    env = dict(os.environ, RUST_LOG="off", NO_COLOR="1")
    env.pop("ORBIEN_ISSUE20_MISSING_ENV_7C01", None)
    result = subprocess.run(
        [str(arg) for arg in command], cwd=cwd, env=env,
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=TIMEOUT,
    )
    output = result.stdout + result.stderr
    if result.returncode != expected_code:
        raise AssertionError(
            f"{command}: wanted exit {expected_code}, got {result.returncode}\n{output}"
        )
    if reason is not None and reason not in output:
        raise AssertionError(f"{command}: missing reason {reason!r}\n{output}")
    if expected_code == 0 and "--check-config" in map(str, command):
        if "configuration OK" not in result.stdout:
            raise AssertionError(f"missing success marker: {command}\n{output}")
    elif "configuration OK" in output:
        raise AssertionError(f"invalid config reported success: {command}\n{output}")
    return result


def cli(binary, path, cwd, code=0, reason=None):
    return invoke([binary, "--check-config", "-c", path], cwd, code, reason)


def tls_paths(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"certFile", "cert_file", "trustedCaFile", "trusted_ca_file"} and item:
                yield item, "cert"
            elif key in {"keyFile", "key_file"} and item:
                yield item, "key"
            else:
                yield from tls_paths(item)
    elif isinstance(value, list):
        for item in value:
            yield from tls_paths(item)


def role(path):
    if path.name.startswith("orbien-server"):
        return "server"
    if path.name in {"orbien.toml", "orbien-full.toml"}:
        return "client"
    raise AssertionError(f"unclassified example config (add an explicit role): {path}")


def run(bin_dir):
    suffix = ".exe" if os.name == "nt" else ""
    binaries = {"server": bin_dir / f"orbien-server{suffix}", "client": bin_dir / f"orbien{suffix}"}
    for binary in binaries.values():
        if not binary.is_file():
            raise AssertionError(f"missing binary: {binary}; build both binaries first")
    if shutil.which("openssl") is None:
        raise AssertionError("openssl is required to generate temporary test certificates")

    with tempfile.TemporaryDirectory(prefix="orbien-config-check-") as temporary:
        work = Path(temporary).resolve()
        cert, key = work / "fixture.crt", work / "fixture.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ], check=True, capture_output=True, timeout=30)

        samples = []
        for relative in [Path("conf"), Path("docker/conf")]:
            source = ROOT / relative
            destination = work / relative
            shutil.copytree(source, destination)
            files = sorted(source.rglob("*.toml"))
            if not files:
                raise AssertionError(f"no configs found under {source}")
            for original in files:
                sample = destination / original.relative_to(source)
                data = tomllib.loads(sample.read_text(encoding="utf-8"))
                for configured, kind in tls_paths(data):
                    target = (sample.parent / configured).resolve()
                    if not target.is_relative_to(work):
                        raise AssertionError(f"fixture path escapes temporary tree: {configured}")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(key if kind == "key" else cert, target)
                if original.read_bytes() != sample.read_bytes():
                    raise AssertionError(f"sample was rewritten: {original}")
                cli(binaries[role(original)], sample, work)
                if original.read_bytes() != sample.read_bytes():
                    raise AssertionError(f"checker rewrote sample: {original}")
                samples.append(original.relative_to(ROOT))

        bad_root = ROOT / "tests/config/bad"
        bad_files = sorted(bad_root.rglob("*.toml"))
        if not bad_files:
            raise AssertionError("known-bad corpus must not be empty")
        for original in bad_files:
            target = work / "bad" / original.relative_to(bad_root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
            first = original.read_text(encoding="utf-8").splitlines()[0]
            marker = "# expect-error: "
            if not first.startswith(marker) or original.parent.name not in binaries:
                raise AssertionError(f"missing expected reason or unknown role: {original}")
            cli(binaries[original.parent.name], target, work, 1, first[len(marker):])

        # The parent owns occupied TCP/UDP sockets. The checker must not try
        # to bind any configured listener or connect even to a reachable peer.
        with (
            socket.socket() as tcp,
            socket.socket() as dashboard,
            socket.socket() as http,
            socket.socket() as https,
            socket.socket(type=socket.SOCK_DGRAM) as quic,
            socket.socket(type=socket.SOCK_DGRAM) as kcp,
        ):
            for listener in [tcp, dashboard, http, https]:
                listener.bind(("127.0.0.1", 0))
            tcp.listen(1)
            quic.bind(("127.0.0.1", 0))
            kcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            server = work / "occupied-server.toml"
            server.write_text(
                f'listen = "127.0.0.1:{port}"\n'
                f'quicPort = {quic.getsockname()[1]}\n'
                f'kcpPort = {kcp.getsockname()[1]}\n'
                f'httpGwPort = {http.getsockname()[1]}\n'
                f'httpsGwPort = {https.getsockname()[1]}\n'
                f'[dashboard]\naddr = "127.0.0.1"\nport = {dashboard.getsockname()[1]}\ndisableAuth = true\n',
                encoding="utf-8",
            )
            cli(binaries["server"], server, work, reason="tls-not-forced")
            client = work / "reachable-client.toml"
            client.write_text(f'server = "127.0.0.1:{port}"\n', encoding="utf-8")
            cli(binaries["client"], client, work, reason="no-server-trust")
            tcp.setblocking(False)
            try:
                accepted, _ = tcp.accept()
            except BlockingIOError:
                pass
            else:
                accepted.close()
                raise AssertionError("offline check connected to the server")

        for protocol in ["tcp", "websocket", "kcp", "quic"]:
            client = work / f"no-dns-{protocol}.toml"
            store = work / f"pins-{protocol}.txt"
            client.write_text(
                'server = "must-not-resolve.invalid:9527"\n'
                f'[transport]\nprotocol = "{protocol}"\n'
                f'[transport.tls]\ntofuStoreFile = "{store.as_posix()}"\n',
                encoding="utf-8",
            )
            cli(binaries["client"], client, work)
            if store.exists() or store.with_suffix(".tmp").exists():
                raise AssertionError("offline check wrote a TOFU pin")

        # Verify environment expansion through both real CLI entry points.
        for name, field in [("server", "listen"), ("client", "server")]:
            config = work / f"env-{name}.toml"
            config.write_text(f'{field} = "{{{{env.ORBIEN_ISSUE20_MISSING_ENV_7C01:127.0.0.1:9527}}}}"\n', encoding="utf-8")
            cli(binaries[name], config, work)
            invoke([binaries[name], "--check-config", "--not-a-real-option"], work, 2, "unexpected argument")
            cli(binaries[name], work / "does-not-exist.toml", work, 1, "not found" if name == "client" else "failed to read config file")

        print(f"checked {len(samples)} unchanged sample configs and {len(bad_files)} known-bad configs")
        for sample in samples:
            print(f"  OK {sample}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "target/debug")
    args = parser.parse_args()
    run(args.bin_dir.resolve())
