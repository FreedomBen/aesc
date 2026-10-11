#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Pure-Ruby runner for the aesc CLI end-to-end suite. We avoid Rake because
# this environment ships no `rake` gem; this loads every cases/**/*_test.rb and
# lets minitest run them. Any arguments are passed through to minitest:
#
#   ruby runner.rb                 # run all cases
#   ruby runner.rb -n /round_trip/ # filter by name
#   ruby runner.rb --seed 1234     # fix the randomization seed
#
# Normally invoked through run.sh, which builds the binary first.

$LOAD_PATH.unshift(__dir__)
require "test_helper"

unless File.executable?(Aesc.binary)
  warn "aesc binary not found at #{Aesc.binary}"
  warn "build it first:  cargo build -p aesc-cli   (or set AESC_BIN)"
  exit 1
end

cases = Dir.glob(File.join(__dir__, "cases", "**", "*_test.rb")).sort
warn "aesc E2E: binary=#{Aesc.binary}  cases=#{cases.size}"
cases.each { |file| require file }

# minitest/autorun (pulled in via test_helper) runs the loaded cases at exit.
