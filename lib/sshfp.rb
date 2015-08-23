require 'base64'
require 'digest'

module SSHFP
  class Parser
    def parse(data)
      lines = data.split("\n")
      lines.map do |l|
        next if /^#/.match l
        pieces = parse_line l
        Entry.new(*pieces)
      end.reject(&:nil?)
    end

    protected

    def parse_line(l)
      host, *remainder = l.split(' ')
      port = 22
      m = /\A\[(.*?)\]:(\d+)\z/.match host
      if m
        host = m[1]
        port = m[2]
      end
      [host, port, *remainder]
    end
  end

  Entry = Struct.new(:host, :port, :algo, :key) do
    # Always use SHA-256.
    def digest
      hash = Digest::SHA2.new(256)
      hash << Base64.strict_decode64(key)
      hash.hexdigest.upcase
    end

    def algo_number
      case algo
      when 'ssh-rsa'
        1
      when 'ssh-dss'
        2
      when /\Aecdsa-/
        3
      when 'ssh-ed25519'
        4
      end
    end

    def to_s
      "#{host} IN SSHFP #{algo_number} 2 #{digest}"
    end
  end
end
