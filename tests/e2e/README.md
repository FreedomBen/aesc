# aesc CLI — end-to-end test suite

Black-box tests that drive the **real built `aesc` binary** the way a user
would from a shell: encrypting and decrypting real files, exercising password
and keyfile plumbing, shell pipelines, exit codes, and the on-disk format.

## Scope (and how it differs from the Rust tests)

The `aesc-cli` crate already has in-process `assert_cmd` integration tests
(`crates/aesc-cli/tests/it_*.rs`) covering cipher, flags, info, IO errors,
round-trip, secret handling, and stdio. This suite is **complementary** — it
covers what only an external, full-binary test can:

- the compiled binary as invoked from a shell (args, env vars, exit codes);
- real shell pipelines / redirection (`… | aesc -e - | aesc -d - > out`);
- password sources on the real filesystem (`--password-file`, `--password-env`);
- armored output inspected with shell tooling;
- large / binary / chunk-boundary inputs end-to-end;
- committed "golden" ciphertexts for file-format backward-compatibility;
- an exit-code matrix usable as a release smoke test.

Prefer user-visible behavior over re-proving the fine-grained Rust assertions.

## Layout

| Path                             | Purpose                                                                                                                                    |
|----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| `run.sh`                         | Build the CLI (unless `AESC_BIN` is set), then run the suite.                                                                              |
| `runner.rb`                      | Pure-Ruby runner: loads every case and lets minitest run them.                                                                             |
| `test_helper.rb`                 | Base `E2ETest` class: per-test temp dir, the `aesc` runner, and assertions.                                                                |
| `cases/`                         | The test files (`*_test.rb`), one per backlog area.                                                                                        |
| `golden_manifest.rb`             | Single source of truth for the backward-compat goldens (password, plaintext, legacy + current manifests).                                  |
| `regenerate_goldens.rb`          | Deliberate regenerator for the current `.aesc` goldens (refuses to clobber without `--force`; never touches the legacy set).               |
| `templates/example_test.rb.tmpl` | Copy-me starting point (not collected as a test).                                                                                          |
| `../fixtures/`                   | Committed inputs (`LOREM_IPSUM.txt`), the full-size interop ciphertexts (`.aes` / legacy `.paladin` / `.aesc`), and `golden/` ciphertexts. |

There is no Rakefile on purpose: this environment ships no `rake` gem. The runner
is plain Ruby and needs only stdlib — `minitest`, `open3`, `tmpdir`, `fileutils`.

## Running

```sh
make e2e                          # build + run everything (from the repo root)
make e2e ARGS="-n /round_trip/"   # filter by test name

# …or call the runner directly:
tests/e2e/run.sh                  # build + run everything
tests/e2e/run.sh -n /round_trip/  # filter by test name (minitest passthrough)
AESC_BIN=target/release/aesc tests/e2e/run.sh   # test a release build
AESC_E2E_SLOW=1 tests/e2e/run.sh                    # also run the opt-in slow cases
```

The advanced cases (large-file round-trip, SIGINT cancellation) are slow or
timing-sensitive, so they are skipped unless `AESC_E2E_SLOW=1` is set.

## Adding a case

1. `cp templates/example_test.rb.tmpl cases/<area>_test.rb`
2. Subclass `E2ETest` and write `test_*` methods.
3. Use the provided helpers instead of re-rolling them:
   - `aesc(*args, stdin:, env:)` → `Result(status, stdout, stderr)`
   - `tmp(name)`, `write_input`, `make_input(name, size)`, `make_keyfile`
   - `flip_byte`, `set_byte`, `truncate_input` (tamper / truncate cases)
   - `assert_size_grew`, `assert_identical`, `assert_status`, `assert_failure`
   - constants: `Aesc::LOREM`, `Aesc::GOLDEN_DIR`, `DEFAULT_PASSWORD`, `CHUNK`, `FAST_KDF`
4. Each test gets a fresh temp dir (`@tmpdir`), removed automatically on teardown.

## Conventions

- Supply passwords non-interactively (`--password-env`, `--password-file`, `-p`).
  Prefer `--password-env` so secrets never appear in the process argument list.
- Never write outputs next to committed fixtures; use `tmp(...)`. On decrypt,
  pass `--output` so the filename restored from the header can't clobber one.
- Generate sized / binary inputs at runtime; commit only small `golden/` files.
  The full-size interop ciphertexts (`../fixtures/LOREM_IPSUM.txt.aes` /
  `.paladin` / `.aesc`) are the deliberate exception: they are minted by real
  tool runs — one by a foreign tool, one by a pre-dialect-change build that no
  longer exists — and lock the shipped defaults at scale. See
  `../fixtures/README.md`.

## Cases

One file per area; see [E2E_TESTS.md](E2E_TESTS.md) for the per-item checklist
and the behaviors confirmed against the binary.

| File                       | Covers                                                                                                                                               |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------|
| `roundtrip_test.rb`        | Round-trip identity across sizes (empty + 64 KiB boundary), default `.aesc` name.                                                                    |
| `failures_test.rb`         | Exit-code matrix: auth (3), format/version (4), usage/overwrite (2).                                                                                 |
| `cipher_test.rb`           | Both ciphers, header-driven decrypt, `--info`, invalid name, multi-chunk.                                                                            |
| `kdf_test.rb`              | Each KDF + custom costs, out-of-range/mismatched knobs, `--info` params.                                                                             |
| `armor_test.rb`            | Armored round-trip, 7-bit ASCII, banners, default `.asc` name, tamper, leniency.                                                                     |
| `password_sources_test.rb` | `-p` / `--password-file` / `--password-env`, interop, conflicts, unicode.                                                                            |
| `keyfile_test.rb`          | password+keyfile, keyfile-only, wrong/missing keyfile, `-k -`, distinct keys.                                                                        |
| `streaming_test.rb`        | stdin/stdout pipelines, armored streaming, multi-chunk, `-q` stdout purity.                                                                          |
| `info_verify_test.rb`      | `--info` fields / no-write, `--verify` success/tamper/no-write, armored.                                                                             |
| `remove_test.rb`           | `--remove` on success vs. preserved on failure; stdin is a usage error.                                                                              |
| `io_errors_test.rb`        | Exit 1 paths (missing/read-only out dir, unreadable input); dir input → 2.                                                                           |
| `backward_compat_test.rb`  | Decrypt committed goldens — frozen legacy `.paladin` set + current `.aesc` set (cipher×KDF, armored, stdin) — + `--info` lock.                       |
| `interop_fixtures_test.rb` | Committed real-tool ciphertexts (aescrypt 3.16.1 `.aes`; legacy and current native dialects at defaults) decrypt byte-for-byte; byte-exact `--info`. |
| `misc_test.rb`             | Header authentication / no-downgrade, reserved flags, fresh randomness, help/version.                                                                |
| `advanced_test.rb`         | Opt-in (`AESC_E2E_SLOW=1`): large-file round-trip, SIGINT cancellation.                                                                              |

### Backward-compatibility goldens

`backward_compat_test.rb` decrypts committed ciphertexts in `../fixtures/golden/`
to lock the on-disk format: the FROZEN legacy `.paladin` set (minted by the
pre-dialect-change build; never regenerable) and the current `.aesc` set. Both
are described by `golden_manifest.rb` and decrypt to the small
`golden/plaintext.txt` with the single fixed, documented password. Regenerate
the current set deliberately (only after an intended format/defaults change):

```sh
ruby tests/e2e/regenerate_goldens.rb --force   # --force required to overwrite
```

The script never writes the legacy set. See `../fixtures/golden/README.md` for
the full procedure.
