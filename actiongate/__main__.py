"""CLI: python -m actiongate <command>"""

from __future__ import annotations

import argparse
import getpass
import secrets
import sys

from .config import hash_key, load
from .vault import Vault


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="actiongate")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the HTTP + MCP server")
    s.add_argument("--config", default="actiongate.yaml")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)

    sub.add_parser("vault-key", help="generate a vault encryption key")

    sp = sub.add_parser("put-secret", help="store a connector credential in the vault (prompts for value)")
    sp.add_argument("name")
    sp.add_argument("--vault", default="data/vault.bin")

    sub.add_parser("new-key", help="generate an agent key or approver token and its config hash")

    v = sub.add_parser("verify-audit", help="verify the audit chain")
    v.add_argument("--config", default="actiongate.yaml")

    args = p.parse_args(argv)

    if args.cmd == "vault-key":
        print(Vault.generate_key())
        return 0
    if args.cmd == "put-secret":
        Vault(args.vault).put(args.name, getpass.getpass(f"value for {args.name}: "))
        print(f"stored '{args.name}'")
        return 0
    if args.cmd == "new-key":
        raw = "agk_" + secrets.token_urlsafe(32)
        print(f"key (give to the agent or approver, shown once): {raw}")
        print(f"key_sha256 / token_sha256 (put in config):       {hash_key(raw)}")
        return 0
    if args.cmd == "verify-audit":
        r = load(args.config).gateway.audit.verify()
        print(f"ok={r.ok} records={r.records}" + (f" error={r.error} at seq {r.bad_seq}" if not r.ok else ""))
        return 0 if r.ok else 1
    if args.cmd == "serve":
        import uvicorn

        from .server import create_app

        uvicorn.run(create_app(load(args.config)), host=args.host, port=args.port)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
