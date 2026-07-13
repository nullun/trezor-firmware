# Algorand modular app

Algorand external application for Trezor. Derives ed25519 keys, encodes the
canonical Algorand address, and signs one or more canonical-msgpack
transactions (single or atomic group, including chunked uploads for large
payloads).

## Building

From `sdk/apps`:

```sh
cargo xtask build -p algorand --model t3w1 --lang en --emulator
```

## Testing

Device tests use the standard Trezor pytest harness (the same flow
`cargo xtask device-tests` drives) and run against the emulator. Build the
emulator artifact first, then:

```sh
cargo xtask device-tests -p algorand --model t3w1 --emulator
```

Or run pytest directly from this app directory (`sdk/apps/algorand`), so its
`pyproject.toml` is picked up as the pytest rootdir and the `--app`/`--ui`
options registered in `tests/conftest.py` are recognized. The build artifact
lives in the workspace `target/` one level up, and the emulator must already
be running:

```sh
uv run pytest --app=../target/artifacts/t3w1-emu/algorand.elf --ui=test
```

Pass `--ui=record` instead of `--ui=test` to regenerate
`tests/ui_tests/fixtures.json` after intentional UI changes.

The protobuf message classes in `tests/generated/messages.py` are
regenerated from `protob/*.proto` at the start of every test session, so the
wire schema stays in sync with the firmware.

## Display notes

Asset amounts (asset transfer, asset config `Total`) are shown in the asset's
**raw base units**, not adjusted for the asset's decimals. The decimal exponent
lives in the asset's on-chain parameters, which aren't part of the transaction
the device signs, so the device has no trustworthy way to scale the figure — it
shows exactly the integer that will be committed. Only ALGO amounts (`Amount`,
`Fee` on payments) are rendered as decimal ALGO, because the microAlgo→ALGO
factor (1e6) is fixed by the protocol.

## Manual scripts

`scripts/` holds standalone smoke-test and fuzzing tools run directly with
`uv run python scripts/<name>.py` — see `scripts/test_fuzz_sign.py` for the
randomized differential fuzzer (requires `algosdk` + `msgpack`).
