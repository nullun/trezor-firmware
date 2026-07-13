"""Shared helpers for locating and loading a built modular app.

`cargo xtask build` publishes the loadable artifact to
`target/artifacts/<model>[-emu]/<app>.elf` (see modular-xtask
`postbuild::publish_artifact`). The published path encodes model and
emulator-vs-hardware, but NOT debug-vs-production — both profiles overwrite the
same file — so selecting a build means choosing `--model` and
`--hardware`/emulator. `--app-path` is the escape hatch for loading an
unpublished binary directly (e.g. `target/debug-fw/algorand`).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# scripts live in sdk/apps/<app>/scripts/, so three levels up is sdk/apps.
_TARGET_DIR = Path(__file__).resolve().parent.parent.parent / "target"

MODELS = ("t3t1", "t3w1")


def add_app_args(parser: argparse.ArgumentParser) -> None:
    """Register the standard app-selection options on `parser`."""
    group = parser.add_argument_group("app selection")
    group.add_argument(
        "--app", default="algorand", help="App crate name (default: algorand)"
    )
    group.add_argument(
        "--model",
        choices=MODELS,
        default="t3w1",
        help="Target model (default: t3w1)",
    )
    group.add_argument(
        "--hardware",
        action="store_true",
        help="Load the hardware build instead of the emulator build",
    )
    group.add_argument(
        "--app-path",
        type=Path,
        default=None,
        help="Explicit path to the app binary, bypassing artifact resolution",
    )


def resolve_app_path(args: argparse.Namespace) -> Path:
    """Resolve the published artifact path from parsed `args`."""
    if args.app_path is not None:
        return args.app_path
    model_dir = f"{args.model}{'' if args.hardware else '-emu'}"
    return _TARGET_DIR / "artifacts" / model_dir / f"{args.app}.elf"


def load_app(session, args: argparse.Namespace) -> int:
    """Locate, read and load the app onto `session`; returns the instance id."""
    # Imported lazily so callers control trezorlib resolution (the fuzz script
    # prepends the local monorepo path before importing trezorlib).
    from trezorlib import trezorapp

    app_path = resolve_app_path(args)
    if not app_path.exists():
        build = f"cargo xtask build -p {args.app} --model {args.model}"
        if not args.hardware:
            build += " --emulator"
        sys.exit(
            f"App binary not found: {app_path}\n"
            f"Build it first, e.g.:\n    {build}"
        )
    print(f"Loading app from: {app_path}")
    # proof=b"" / min_version=None: dev loads carry no signed proof and accept
    # the binary's own header version (mirrors trezorlib's debuglink loader).
    # force_reload is intentionally left False: it makes trezorlib send
    # sha256(elf) as the expected hash, but the firmware's image.get_hash()
    # isn't that sha256, so the post-upload match check always fails ("Failed
    # to load app"). A same-version rebuild is therefore reused, not
    # re-uploaded — restart the emulator to pick up a fresh build.
    return trezorapp.load(session, app_path.read_bytes(), b"", None)
