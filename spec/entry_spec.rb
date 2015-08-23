require_relative 'spec_helper'

describe SSHFP::Entry do
  def default_ed25519_key
    'AAAAC3NzaC1lZDI1NTE5AAAAIBp57FMx9cymiY43bPuhmS6fhC2q8dBE7/G5+IO2iXrb'
  end

  def default_ed25519
    SSHFP::Entry.new('s1.example.tld', 22, 'ssh-ed25519', default_ed25519_key)
  end

  it 'should have valid attributes' do
    r = default_ed25519
    expect(r.host).to eq 's1.example.tld'
    expect(r.port).to eq 22
    expect(r.algo).to eq 'ssh-ed25519'
    expect(r.key).to eq default_ed25519_key
  end

  it 'should compute digests correctly' do
    r = default_ed25519
    digest = 'bcf5c33a33904b5ed5b61be660af43e2f23e39149cbba18485e72e70dec6c3ec'
    expect(r.digest.downcase).to eq digest
  end

  it 'should detect the algorithm number correctly for ED25519 keys' do
    r = default_ed25519
    expect(r.algo_number).to eq 4
  end

  it 'should generate valid SSHFP records for to_s' do
    r = default_ed25519
    pieces = %w(
      s1.example.tld
      IN
      SSHFP
      4
      2
      BCF5C33A33904B5ED5B61BE660AF43E2F23E39149CBBA18485E72E70DEC6C3EC
    )
    expect(r.to_s).to eq pieces.join(' ')
  end
end
