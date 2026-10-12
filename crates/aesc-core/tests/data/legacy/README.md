# Legacy paladin-dialect fixtures

Genuine pre-dialect-change containers, minted on 2026-10-12 by the **last build
that wrote the legacy dialect** (commit `9d34429`, the rename commit): PALADIN
magic, `paladin secret v1` KDF domain tag, and `PALADIN MESSAGE` armor markers
(DESIGN §5.2, §5.6, §14). They can never be regenerated — current builds only
write the aesc dialect — so treat them as frozen: these files are what proves
the legacy read path still works.

Exercised by `tests/integration.rs::legacy_paladin_fixtures_decrypt_inspect_and_verify`.

| File             | Contents                                                                                   |
|------------------|----------------------------------------------------------------------------------------------|
| `v1.paladin`     | Binary container: AES-256-GCM / PBKDF2 (10000 iterations), stored filename `legacy.txt`.     |
| `v1.paladin.asc` | Armored container: ChaCha20-Poly1305 / PBKDF2 (10000 iterations), no stored filename.        |

Both decrypt to the exact bytes

```
paladin legacy container fixture: encrypted by the last pre-aesc-dialect build.\n
```

with the password `paladin legacy fixture password` (public on purpose — the
fixtures protect nothing; they exist only to be decrypted by the tests). They
were created with:

```sh
# at commit 9d34429, before the dialect change landed
aesc -e legacy.txt -o v1.paladin     --kdf pbkdf2 --pbkdf2-iterations 10000 \
     --password-env PW --name
aesc -e legacy.txt -o v1.paladin.asc --kdf pbkdf2 --pbkdf2-iterations 10000 \
     --password-env PW -a -c chacha20-poly1305
```

PBKDF2 at the minimum cost keeps the test fast; the cipher × KDF matrix for the
legacy dialect is additionally locked by the frozen in-source KAT vectors
(`src/stream.rs::LEGACY_KAT_VECTORS`) and the e2e goldens
(`tests/fixtures/golden/`).
