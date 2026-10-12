# frozen_string_literal: true
#
# Committed full-size fixtures minted by REAL tool runs, decrypted byte-for-byte:
#
#   ../fixtures/LOREM_IPSUM.txt.aes      — genuine AES Crypt CLI (aescrypt 3.16.1,
#                                          Stream Format 2)
#   ../fixtures/LOREM_IPSUM.txt.paladin  — pre-dialect-change paladin CLI at
#                                          shipped defaults (aes-256-gcm /
#                                          argon2id 65536,3,1): the FROZEN
#                                          legacy dialect (PALADIN magic,
#                                          legacy domain tag — DESIGN §14)
#   ../fixtures/LOREM_IPSUM.txt.aesc     — aesc CLI at shipped defaults: the
#                                          dialect new files are written in
#                                          (aesc magic)
#
# All decrypt to ../fixtures/LOREM_IPSUM.txt (~294 KiB). What this locks that
# the goldens and the Rust suites don't:
#
# - AES Crypt interop at scale: the committed Rust `.aes` fixtures are tiny
#   (<= 3000 B); this one is thousands of CBC blocks plus the final
#   padding/HMAC path, driven through the real binary from a shell.
# - Native containers (both dialects) with a multi-chunk (> 64 KiB) body at the
#   shipped DEFAULT KDF costs — the goldens deliberately use reduced costs and
#   a small plaintext, so they never exercise defaults at scale.
# - Legacy-extension compatibility: both historical suffixes (`.paladin` and
#   `.aes`) must keep decrypting even though new files are written as `.aesc`.
#
# Fixed password for all three files: "password" (public on purpose — the
# fixtures protect nothing; they exist only to be decrypted here). See
# ../fixtures/README.md for provenance and regeneration.

require "test_helper"

class InteropFixturesTest < E2ETest
  PASSWORD = "password"
  AES_FIXTURE     = File.join(Aesc::FIXTURES_DIR, "LOREM_IPSUM.txt.aes")
  PALADIN_FIXTURE = File.join(Aesc::FIXTURES_DIR, "LOREM_IPSUM.txt.paladin")
  AESC_FIXTURE    = File.join(Aesc::FIXTURES_DIR, "LOREM_IPSUM.txt.aesc")
  FIXTURES = { "LOREM_IPSUM.txt.aes" => AES_FIXTURE,
               "LOREM_IPSUM.txt.paladin" => PALADIN_FIXTURE,
               "LOREM_IPSUM.txt.aesc" => AESC_FIXTURE }.freeze

  # `--info` blocks pinned byte-exact (same discipline as it_info.rs /
  # it_aescrypt.rs). Built from a line array so the trailing space on the empty
  # `name:` line is visible in quotes and can't be stripped by an editor.
  AES_INFO = [
    "format: aescrypt",
    "version: 2",
    "cipher: aes-256-cbc",
    "kdf: aescrypt-sha256",
    "kdf_iterations: 8192",
    "extensions: 2",
    "created_by: aescrypt 3.16.1",
    "authenticated: false",
  ].map { |l| "#{l}\n" }.join.freeze

  PALADIN_INFO = [
    "format: aesc (legacy paladin container)",
    "version: 1",
    "cipher: aes-256-gcm",
    "kdf: argon2id",
    "kdf_params: memory=65536,time=3,parallelism=1",
    "flags: 0x00",
    "keyfile_hint: false",
    "chunk_size: 65536",
    "salt_len: 16",
    "nonce_prefix_len: 7",
    "name_status: absent",
    "name: ",
  ].map { |l| "#{l}\n" }.join.freeze

  # The current dialect differs only on the format line.
  AESC_INFO = PALADIN_INFO.sub(
    "format: aesc (legacy paladin container)\n", "format: aesc\n"
  ).freeze

  def assert_fixture_present(path)
    assert File.file?(path),
           "missing committed fixture #{path} — see tests/fixtures/README.md"
  end

  def decrypt_fixture(path, out)
    aesc("-d", path, "-o", out, "--password-env", "FPW",
            env: { "FPW" => PASSWORD })
  end

  # The genuine aescrypt-minted file decrypts byte-for-byte to the committed
  # plaintext: real-tool interop, not just round-tripping our own writer.
  def test_aescrypt_fixture_decrypts_byte_for_byte
    assert_fixture_present AES_FIXTURE
    out = tmp("from_aes.txt")
    res = decrypt_fixture(AES_FIXTURE, out)
    assert_status res, 0, "aescrypt fixture failed to decrypt"
    assert_identical Aesc::LOREM, out
  end

  # The committed pre-dialect-change container (multi-chunk, shipped default
  # costs, FROZEN legacy dialect) decrypts byte-for-byte — the full-size lock
  # on the legacy read path.
  def test_paladin_fixture_decrypts_byte_for_byte
    assert_fixture_present PALADIN_FIXTURE
    out = tmp("from_paladin.txt")
    res = decrypt_fixture(PALADIN_FIXTURE, out)
    assert_status res, 0, "paladin fixture failed to decrypt"
    assert_identical Aesc::LOREM, out
  end

  # The committed current-dialect container (multi-chunk, shipped default
  # costs) decrypts byte-for-byte — the same full-size lock for the dialect new
  # files are written in.
  def test_aesc_fixture_decrypts_byte_for_byte
    assert_fixture_present AESC_FIXTURE
    out = tmp("from_aesc.txt")
    res = decrypt_fixture(AESC_FIXTURE, out)
    assert_status res, 0, "aesc fixture failed to decrypt"
    assert_identical Aesc::LOREM, out
  end

  # `--info` needs no password and reports the exact metadata each fixture was
  # minted with — locking header parsing, the aescrypt created_by/extensions
  # fields, and the shipped defaults recorded in the container.
  def test_info_blocks_are_byte_exact
    { AES_FIXTURE => AES_INFO, PALADIN_FIXTURE => PALADIN_INFO,
      AESC_FIXTURE => AESC_INFO }.each do |path, expected|
      assert_fixture_present path
      res = aesc("-i", path)
      assert_status res, 0, "info failed on #{File.basename(path)}"
      assert_equal expected, res.stdout, "#{File.basename(path)} --info drifted"
    end
  end

  # `--verify` (decrypt-and-discard) accepts every fixture with the fixed
  # password.
  def test_verify_accepts_all_fixtures
    FIXTURES.each do |name, path|
      assert_fixture_present path
      res = aesc("--verify", path, "--password-env", "FPW",
                    env: { "FPW" => PASSWORD })
      assert_status res, 0, "verify failed on #{name}"
    end
  end

  # A wrong password is the same unified auth failure (exit 3) for every
  # format — AES Crypt files get no distinguishable error either.
  def test_wrong_password_is_auth_failure_for_every_format
    FIXTURES.each do |name, path|
      assert_fixture_present path
      out = tmp("wrong-#{name}.out")
      res = aesc("-d", path, "-o", out, "--password-env", "FPW",
                    env: { "FPW" => "not the fixture password" })
      assert_failure res, 3, "authentication failed"
      refute File.exist?(out), "#{name}: no output may remain on auth failure"
    end
  end
end
