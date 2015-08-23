# Coverage has to go before other requires.
if ENV['COVERAGE']
  require 'simplecov'

  SimpleCov.start
end

require_relative '../lib/sshfp'
