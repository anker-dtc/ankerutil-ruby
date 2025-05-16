require 'test/unit'
require_relative '../lib/ankerutil'

class SensitiveDataTest < Test::Unit::TestCase
  def setup
    @sensitive_data = Ankerutil::SensitiveData.new
    @cbc_key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    @root_key = { '0001' => '0123456789abcdef0123456789abcdef' }
    @test_data = 'Hello, World!'

    @sensitive_data.init_sensitive_key(@cbc_key, @root_key)
  end

  def test_initialization
    assert_equal @cbc_key, @sensitive_data.sensitive_data_key
    assert_equal @root_key['0001'], @sensitive_data.sensitive_root_key['0001']
    assert_equal '0001', @sensitive_data.sensitive_root_key_version
    assert_equal @root_key['0001'], @sensitive_data.sensitive_root_key_value
  end

  def test_encrypt_decrypt
    encrypted = @sensitive_data.aes128_sha256_encrypt_sensitive_data(@test_data)
    decrypted = @sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
    
    puts "原文: #{@test_data}"
    puts "密文: #{encrypted}"
    puts "解密后: #{decrypted}"
    puts "解密成功: #{decrypted == @test_data}"
    
    assert_equal @test_data, decrypted
  end

  def test_decrypt_go_encrypted_data
    # Go生成的密文
    go_encrypted = '0001^wKOCCRx4+rg2SEdxXXxXUvppZGv8v7cfCn05fK+IofGM73bHwEvZG235ocHfsA64XhUnIzgQqLWRkmmr3YfKfw==^dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f^x1QVsjF9cL09/Fog3Jnbth0+SJgZ87AaAqSdItkt13M='
    
    decrypted = @sensitive_data.aes128_sha256_decrypt_sensitive_data(go_encrypted)
    assert_equal @test_data, decrypted
  end

  def test_empty_input
    assert_equal '', @sensitive_data.aes128_sha256_encrypt_sensitive_data('')
    assert_equal '', @sensitive_data.aes128_sha256_decrypt_sensitive_data('')
  end

  def test_lowercase_encryption
    test_data = 'Hello, World!'
    encrypted = @sensitive_data.lower_aes128_sha256_encrypt_sensitive_data(test_data)
    decrypted = @sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
    assert_equal test_data.downcase, decrypted
  end
end