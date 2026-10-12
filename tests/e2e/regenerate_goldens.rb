#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Regenerate the CURRENT-dialect backward-compatibility goldens in
# tests/fixtures/golden/ (the `.aesc` set from golden_manifest.rb).
#
# This is a DELIBERATE, REVIEWED step — goldens exist to catch accidental
# on-disk-format changes, so they must never be overwritten casually. The script
# refuses to clobber existing goldens unless you pass --force, and it prints a
# git diff hint so the regeneration lands in a reviewable commit.
#
# The FROZEN legacy `.paladin` goldens (Golden.legacy_manifest) are never
# touched here: they were minted by the pre-dialect-change build and no build
# can write that dialect anymore (DESIGN §14). Only the current `.aesc` set is
# regenerable.
#
#   ruby tests/e2e/regenerate_goldens.rb           # create goldens (won't clobber)
#   ruby tests/e2e/regenerate_goldens.rb --force   # intentionally rewrite them
#   AESC_BIN=target/release/aesc ruby tests/e2e/regenerate_goldens.rb
#
# Ciphertext is non-deterministic (random salt/nonce per file), so regenerating
# changes the bytes every time; that is expected. The test never compares bytes —
# it decrypts with the fixed password and checks the result + header metadata.

require "open3"
require_relative "golden_manifest"

force = ARGV.include?("--force")

unless File.executable?(Golden.binary)
  warn "aesc binary not found at #{Golden.binary}"
  warn "build it first:  cargo build -p aesc-cli   (or set AESC_BIN)"
  exit 1
end

unless File.file?(Golden::PLAINTEXT)
  warn "canonical plaintext missing: #{Golden::PLAINTEXT}"
  exit 1
end

# Only the current-dialect set is generated; a legacy entry here is a manifest
# bug, caught before anything is written.
targets = Golden.current_manifest
if targets.any? { |g| g[:legacy] }
  warn "BUG: Golden.current_manifest contains a frozen legacy golden"
  exit 1
end

existing = targets.map { |g| g[:path] }.select { |p| File.exist?(p) }
if existing.any? && !force
  warn "Refusing to overwrite #{existing.size} existing golden(s):"
  existing.each { |p| warn "  #{p}" }
  warn "Re-run with --force to deliberately regenerate them."
  exit 1
end

def run!(args, stdin: nil)
  out, err, status = Open3.capture3(
    { "GPW" => Golden::PASSWORD }, Golden.binary, *args,
    stdin_data: stdin.nil? ? "" : stdin, binmode: true
  )
  return if status.exitstatus.zero?

  warn "golden generation failed (exit #{status.exitstatus}): aesc #{args.join(' ')}"
  warn err
  warn out
  exit 1
end

targets.each do |g|
  # -f lets aesc overwrite an existing golden; the script-level --force guard
  # above is what actually decides whether we regenerate at all.
  base = %W[--cipher #{g[:cipher]} --kdf #{g[:kdf]}] + g[:cost] + %w[--password-env GPW -f]
  base << "-a" if g[:armored]
  if g[:from_stdin]
    # Encrypt from stdin: no input path, so no original filename is stored.
    run!(["-e", "-", "-o", g[:path], *base], stdin: File.binread(Golden::PLAINTEXT))
  else
    run!(["-e", Golden::PLAINTEXT, "-o", g[:path], *base])
  end
  puts "wrote #{g[:file]}  (#{File.size(g[:path])} B, #{g[:cipher]} / #{g[:kdf]})"
end

puts
puts "Generated #{targets.size} goldens in #{Golden::DIR}"
puts "Review and commit them deliberately, e.g.:"
puts "  git add tests/fixtures/golden && git status"
