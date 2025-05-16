require 'test/unit'
require_relative '../lib/ankerutil'

class EncryptionInteroperabilityTest < Test::Unit::TestCase
  def setup
    @sensitive_data = AnkerUtil::SensitiveData.new
    
    # 统一的测试密钥
    @cbc_key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    @root_key = { '0001' => '0123456789abcdef0123456789abcdef' }

    # 各种测试数据
    @test_cases = [
      'Hello, World!',
      '这是中文测试',
      'Special chars: !@#$%^&*()',
      '1234567890',
      'Mixed 混合 Text',
      'Very long text ' * 10,
      ' ',  # 空格
      'a',   # 单字符
      '{"key": "value"}',  # JSON 字符串
      "Multi\nLine\nText"  # 多行文本
    ]

    @sensitive_data.init_sensitive_key(@cbc_key, @root_key)
  end

  def test_basic_encryption_decryption
    @test_cases.each do |test_data|
      encrypted = @sensitive_data.aes128_sha256_encrypt_sensitive_data(test_data)
      decrypted = @sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
      
      assert_equal test_data, decrypted
      assert_includes encrypted, '0001^'  # 验证版本号
      assert_equal 4, encrypted.split('^').length  # 验证格式
    end
  end

  def test_encryption_format
    encrypted = @sensitive_data.aes128_sha256_encrypt_sensitive_data('test')
    parts = encrypted.split('^')
    
    assert_equal 4, parts.length
    assert_equal '0001', parts[0]  # 版本号
    assert_not_empty parts[1]  # 信封密钥
    assert_match(/^[a-f0-9]{64}$/, parts[2])  # SHA256 摘要
    assert_not_empty parts[3]  # 加密数据
  end

  def test_cross_language_encryption
    @test_cases.each do |test_data|
      encrypted = @sensitive_data.aes128_sha256_encrypt_sensitive_data(test_data)
      decrypted = @sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
      
      # 打印加密结果供其他语言使用
      puts "\n测试数据: #{test_data}"
      puts "加密结果: #{encrypted}"
      puts "解密结果: #{decrypted}"
      puts "解密成功: #{decrypted == test_data}"
      
      assert_equal test_data, decrypted
    end
  end

  def test_decrypt_other_language_ciphertext
    encrypted = @sensitive_data.aes128_sha256_encrypt_sensitive_data('Hello, World!')
    decrypted = @sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
    assert_equal 'Hello, World!', decrypted
  end

  def test_empty_string_handling
    encrypted = @sensitive_data.aes128_sha256_encrypt_sensitive_data('')
    assert_equal '', encrypted
    
    decrypted = @sensitive_data.aes128_sha256_decrypt_sensitive_data('')
    assert_equal '', decrypted
  end

  def test_nil_handling
    encrypted = @sensitive_data.aes128_sha256_encrypt_sensitive_data(nil)
    assert_equal '', encrypted
    
    decrypted = @sensitive_data.aes128_sha256_decrypt_sensitive_data(nil)
    assert_equal '', decrypted
  end

  def test_invalid_ciphertext_handling
    invalid_ciphertexts = [
      'invalid',
      'invalid^text',
      '0001^invalid^text',
      '0001^invalid^text^more^parts',
      '0002^valid^text^parts'  # 未知版本号
    ]

    invalid_ciphertexts.each do |invalid_text|
      result = @sensitive_data.aes128_sha256_decrypt_sensitive_data(invalid_text)
      assert_equal '', result
    end
  end

  def test_large_data_handling
    large_text = 'Performance test data ' * 1000
    encrypted = @sensitive_data.aes128_sha256_encrypt_sensitive_data(large_text)
    decrypted = @sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
    assert_equal large_text, decrypted
  end
end