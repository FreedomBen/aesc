# frozen_string_literal: true
#
# Backward compatibility: decrypt committed "golden" containers produced by an
# earlier build so a future format change can't silently break old files
# (DESIGN §5 is the on-disk contract). The goldens live in tests/fixtures/golden/
# and are described by golden_manifest.rb. Two sets are covered (DESIGN §14):
# the FROZEN legacy `.paladin` goldens minted by the pre-dialect-change build
# (PALADIN magic, legacy domain tag — they can never be regenerated) and the
# current `.aesc` goldens (regenerate deliberately with
# tests/e2e/regenerate_goldens.rb; never auto-overwrite, and never the legacy
# set).
#
# Each set covers every cipher × KDF, one armored file, and one stdin-encrypted
# file (no stored filename). All decrypt to the same small canonical plaintext
# with the single fixed golden password.

require "test_helper"
require "golden_manifest"

class BackwardCompatTest < E2ETest
  EXPECTED = File.binread(Golden::PLAINTEXT)

  # Every golden decrypts with the fixed password and reproduces the canonical
  # plaintext byte-for-byte. Armor is auto-detected (no -a on decrypt).
  def test_each_golden_decrypts_to_canonical_plaintext
    Golden.manifest.each do |g|
      assert File.file?(g[:path]), "missing golden #{g[:file]} — run regenerate_goldens.rb"
      out = tmp("#{g[:file]}.out")
      dec = aesc("-d", g[:path], "-o", out, "--password-env", "GPW",
                     env: { "GPW" => Golden::PASSWORD })
      assert_status dec, 0, "golden #{g[:file]} failed to decrypt"
      assert_equal EXPECTED, File.binread(out), "golden #{g[:file]} plaintext mismatch"
    end
  end

  # `--info` on each golden reports the dialect-qualified format line plus the
  # cipher, KDF, params, and name status it was generated with — locking the
  # header layout, the dialect detection, and the recorded KDF costs.
  def test_each_golden_info_reports_expected_metadata
    Golden.manifest.each do |g|
      info = aesc("-i", g[:path])
      assert_status info, 0, "info failed on #{g[:file]}"
      assert_includes info.stdout, "#{g[:format_line]}\n", "#{g[:file]} format line"
      assert_includes info.stdout, "cipher: #{g[:cipher]}\n", "#{g[:file]} cipher"
      assert_includes info.stdout, "kdf: #{g[:kdf]}\n", "#{g[:file]} kdf"
      assert_includes info.stdout, "kdf_params: #{g[:params]}\n", "#{g[:file]} params"
      assert_includes info.stdout, "name_status: #{g[:name_status]}\n", "#{g[:file]} name_status"
    end
  end

  # A wrong password against a golden is an auth failure (exit 3), same as any
  # other container — the goldens are real, authenticated files.
  def test_wrong_password_against_golden_is_auth_failure
    g = Golden.manifest.first
    res = aesc("-d", g[:path], "-o", tmp("o"), "--password-env", "GPW",
                   env: { "GPW" => "not the golden password" })
    assert_failure res, 3, "authentication failed"
  end
end
