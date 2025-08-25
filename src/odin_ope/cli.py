"""Minimal CLI interface for odin_ope.

Usage examples:
  odin-ope sign-envelope --seed <base64url-seed> --payload payload.json \
      --payload-type demo.v1 --target-type example.v1 > signed.json

  odin-ope verify-envelope --envelope signed.json --jwks jwks.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bundle import verify_bundle, verify_bundle_or_raise
from .envelope import build_envelope, sign_envelope
from .exceptions import (
    reason_code_for_exception,
)
from .signers import FileSigner
from .verify import build_jwks_for_signers, verify_envelope, verify_envelope_or_raise


def _load_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


def cmd_sign_envelope(args: argparse.Namespace) -> int:
    signer = FileSigner(args.seed)
    payload = _load_json(args.payload)
    env = build_envelope(
        payload, args.payload_type, args.target_type, trace_id=args.trace_id, ts=args.ts
    )
    if args.not_before:
        env["not_before"] = args.not_before
    if args.expires_at:
        env["expires_at"] = args.expires_at
    signed = sign_envelope(env, signer)
    jwks = build_jwks_for_signers([signer]) if args.emit_jwks else None
    out = {"envelope": signed}
    if jwks:
        out["jwks"] = jwks
    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def _exc_code(e: Exception) -> str:
    return reason_code_for_exception(e)


def cmd_verify_envelope(args: argparse.Namespace) -> int:
    data = _load_json(args.envelope)
    env = data.get("envelope") if "envelope" in data else data
    jwks = _load_json(args.jwks)
    max_skew = None if args.no_skew else args.max_skew
    try:
        verify_envelope_or_raise(env, jwks, max_skew_seconds=max_skew, strict=args.strict)
        if args.json:
            json.dump({"status": "ok"}, sys.stdout)
            sys.stdout.write("\n")
        else:
            print("OK")
        return 0
    except Exception as e:  # intentional broad for CLI
        code = _exc_code(e)
        if args.json:
            json.dump({"status": "error", "code": code, "message": str(e)}, sys.stdout)
            sys.stdout.write("\n")
        else:
            print(f"FAIL: {e}", file=sys.stderr)
            ok, reason = verify_envelope(env, jwks)
            if not ok:
                print(f"reason_code={reason}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("odin-ope")
    sub = p.add_subparsers(dest="cmd", required=True)

    s1 = sub.add_parser("sign-envelope", help="Build and sign an envelope")
    s1.add_argument("--seed", required=True, help="Ed25519 seed base64url (32 bytes decoded)")
    s1.add_argument("--payload", required=True, help="Path to JSON payload file")
    s1.add_argument("--payload-type", required=True)
    s1.add_argument("--target-type", required=True)
    s1.add_argument("--trace-id", help="Optional trace id override")
    s1.add_argument("--ts", help="Optional timestamp override (ISO8601)")
    s1.add_argument("--emit-jwks", action="store_true", help="Include JWKS in output JSON")
    s1.add_argument("--not-before", help="Optional not_before timestamp (ISO8601)")
    s1.add_argument("--expires-at", help="Optional expires_at timestamp (ISO8601)")
    s1.set_defaults(func=cmd_sign_envelope)

    s2 = sub.add_parser("verify-envelope", help="Verify an envelope JSON against JWKS")
    s2.add_argument("--envelope", required=True, help="Path to envelope JSON file")
    s2.add_argument("--jwks", required=True, help="Path to JWKS JSON file")
    s2.add_argument(
        "--max-skew", type=int, default=300, help="Max allowed timestamp skew seconds (default 300)"
    )
    s2.add_argument("--no-skew", action="store_true", help="Disable skew checking")
    s2.add_argument("--strict", action="store_true", help="Enable strict schema validation")
    s2.add_argument("--json", action="store_true", help="Emit JSON result")
    s2.set_defaults(func=cmd_verify_envelope)

    s3 = sub.add_parser("verify-bundle", help="Verify a bundle JSON against JWKS and signature")
    s3.add_argument("--bundle", required=True, help="Path to bundle JSON file")
    s3.add_argument("--jwks", required=True, help="Path to JWKS JSON file")
    s3.add_argument("--kid", required=True, help="Expected signer kid")
    s3.add_argument("--signature", required=True, help="Base64url signature for bundle")
    s3.add_argument(
        "--max-skew",
        type=int,
        default=300,
        help="Max allowed exported_at skew seconds (default 300)",
    )
    s3.add_argument("--no-skew", action="store_true", help="Disable skew checking")
    s3.add_argument(
        "--strict", action="store_true", help="Enable strict schema (currently unused for bundle)"
    )
    s3.add_argument("--json", action="store_true", help="Emit JSON result")

    def _cmd(args: argparse.Namespace) -> int:
        import json
        import sys

        bundle = json.loads(Path(args.bundle).read_text())
        jwks = json.loads(Path(args.jwks).read_text())
        max_skew = None if args.no_skew else args.max_skew
        try:
            verify_bundle_or_raise(
                bundle, args.signature, jwks, args.kid, max_skew_seconds=max_skew
            )
            if args.json:
                json.dump({"status": "ok"}, sys.stdout)
                sys.stdout.write("\n")
            else:
                print("OK")
            return 0
        except Exception as e:
            code = _exc_code(e)
            if args.json:
                json.dump({"status": "error", "code": code, "message": str(e)}, sys.stdout)
                sys.stdout.write("\n")
            else:
                print(f"FAIL: {e}", file=sys.stderr)
                ok, reason = verify_bundle(bundle, args.signature, jwks, args.kid)
                if not ok:
                    print(f"reason_code={reason}", file=sys.stderr)
            return 1

    s3.set_defaults(func=_cmd)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
