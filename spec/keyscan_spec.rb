require_relative 'spec_helper'

describe SSHFP::Parser do
  it 'should create entries when parsing keys' do
    p = SSHFP::Parser.new
    pieces = %w(
      s1.example.tld
      ssh-ed25519
      AAAAC3NzaC1lZDI1NTE5AAAAIBp57FMx9cymiY43bPuhmS6fhC2q8dBE7/G5+IO2iXrb
    )
    line = pieces.join(' ')
    list = p.parse(line)
    expect(list.length).to eq 1
    r = list[0]
    expect(r.class).to be SSHFP::Entry
    expect(r.host).to eq 's1.example.tld'
    expect(r.port).to eq 22
    expect(r.algo).to eq 'ssh-ed25519'
    expect(r.key).to eq pieces[2]
  end
end
