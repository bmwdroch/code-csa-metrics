#!/usr/bin/env python3
"""Start the CSA Metrics web interface.

Usage:
    python run_web.py [--host HOST] [--port PORT]

Environment variables:
    CSA_WEB_TOKEN   The access token that must appear as a URL path prefix.
                    Generate one with:  python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(16)).decode())"
                    If unset, all requests are accepted (development mode only).

Example:
    CSA_WEB_TOKEN=dGVzdHRva2Vu python run_web.py
    # Then open:  http://localhost:8080/dGVzdHRva2Vu/
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Add src/ to the module search path so `web.*` resolves correctly.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import uvicorn  # noqa: E402  (import after sys.path manipulation)


def main() -> None:
    parser = argparse.ArgumentParser(description="CSA Metrics web interface")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload (development)")
    args = parser.parse_args()

    token = os.environ.get("CSA_WEB_TOKEN", "")

    print("=" * 60)
    print("  CSA Metrics — Web Interface")
    print("=" * 60)
    if token:
        print(f"  Access URL : http://{args.host}:{args.port}/{token}/")
    else:
        print("  WARNING: CSA_WEB_TOKEN is not set.")
        print("  All requests are accepted — do not expose publicly!")
        print(f"  URL        : http://{args.host}:{args.port}/<any-string>/")
    print("=" * 60)

    uvicorn.run(
        "web.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
