# Golden ciphertexts (on-disk format lock)

These files are **committed ciphertexts** produced by known builds of the CLI.
The end-to-end suite (`tests/e2e/cases/backward_compat_test.rb`) decrypts them on
every run, so if a future change alters the on-disk format
(`docs/DESIGN.md` §5) in a way that breaks old files, a test fails instead of the
breakage shipping silently.

Since the 2026-10 dialect change (DESIGN §14) there are **two sets**:

- **Legacy `.paladin` set — FROZEN.** Minted by the pre-dialect-change build:
  PALADIN magic, legacy `paladin secret v1` KDF domain tag, PALADIN armor
  markers. No current build can write that dialect, so these files can never be
  regenerated; they are what proves the legacy read path still works. The
  historical `.paladin` filenames are kept on purpose, since decrypting them
  also locks legacy-extension support.
- **Current `.aesc` set.** The dialect new files are written in: aesc magic,
  `aesc secret v1` domain tag, AESC armor markers. Regenerable deliberately
  (see below).

## What's here

| File                                       | Cipher            | KDF      | Notes                                    |
|--------------------------------------------|-------------------|----------|------------------------------------------|
| `plaintext.txt`                            | —                 | —        | Canonical plaintext (the source)         |
| `aes-256-gcm.argon2id.{paladin,aesc}`      | aes-256-gcm       | argon2id | reduced costs                            |
| `aes-256-gcm.scrypt.{paladin,aesc}`        | aes-256-gcm       | scrypt   | reduced costs                            |
| `aes-256-gcm.pbkdf2.{paladin,aesc}`        | aes-256-gcm       | pbkdf2   | reduced costs                            |
| `chacha20-poly1305.argon2id.{…}`           | chacha20-poly1305 | argon2id | reduced costs                            |
| `chacha20-poly1305.scrypt.{…}`             | chacha20-poly1305 | scrypt   | reduced costs                            |
| `chacha20-poly1305.pbkdf2.{…}`             | chacha20-poly1305 | pbkdf2   | reduced costs                            |
| `armored.paladin.asc` / `armored.aesc.asc` | aes-256-gcm       | argon2id | ASCII-armored                            |
| `stdin_no_name.{paladin,aesc}`             | aes-256-gcm       | pbkdf2   | encrypted from stdin; no stored filename |

Each ciphertext decrypts to `plaintext.txt`. They are generated with **reduced
KDF costs** (see `tests/e2e/golden_manifest.rb`): the goldens lock the on-disk
*format*, not the production cost config, and cheap costs keep them fast to
decrypt even in debug builds. The shipped defaults (`docs/DESIGN.md` §12) are
pinned by the core unit tests and the full-size interop fixtures instead.

## Fixed parameters

- **Password:** `paladin golden v1` for BOTH sets (public on purpose — these
  files protect nothing; they exist only to be decrypted by the test). The
  value keeps the original project name: the frozen legacy bytes were encrypted
  with it, so it can never change, and the current set reuses it so there is
  exactly one golden password.
- **Plaintext:** `plaintext.txt` in this directory.

The password and the golden manifests are defined once in
`tests/e2e/golden_manifest.rb`, shared by the test and the regeneration script.

## Regenerating (deliberate, reviewed)

Do **not** regenerate casually — the whole point is that these bytes are stable,
and the `.paladin` set cannot be regenerated at all (the regeneration script
only ever writes the `.aesc` set). Regenerate only when you have intentionally
changed the format or defaults, and land the result in its own reviewed commit:

```sh
cargo build -p aesc-cli
ruby tests/e2e/regenerate_goldens.rb --force   # --force is required to overwrite
git add tests/fixtures/golden && git diff --cached --stat
```

Ciphertext is non-deterministic (random salt/nonce per file), so the bytes change
on every regeneration; that is expected. The test never compares raw bytes — it
decrypts with the fixed password and checks the plaintext plus the `--info`
metadata (including the dialect-qualified `format:` line).
