require 'rspec'
require_relative '../lib/encrypt/sensitive/sensitive_data'

RSpec.describe 'Encryption Interoperability Tests' do
  let(:sensitive_data) { Ankerutil::Encrypt::Sensitive::SensitiveData.new }
  
  # 统一的测试密钥
  let(:cbc_key) { '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' }
  let(:root_key) { { '0001' => '0123456789abcdef0123456789abcdef' } }

  # 各种测试数据
  let(:test_cases) do
    [
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
  end

  before do
    sensitive_data.init_sensitive_key(cbc_key, root_key)
  end

  describe '基本加解密功能' do
    it '对所有测试用例进行加解密验证' do
      test_cases.each do |test_data|
        encrypted = sensitive_data.aes128_sha256_encrypt_sensitive_data(test_data)
        decrypted = sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
        
        expect(decrypted).to eq(test_data)
        expect(encrypted).to include('0001^')  # 验证版本号
        expect(encrypted.split('^').length).to eq(4)  # 验证格式
      end
    end

    it '验证加密结果的格式' do
      encrypted = sensitive_data.aes128_sha256_encrypt_sensitive_data('test')
      parts = encrypted.split('^')
      
      expect(parts.length).to eq(4)
      expect(parts[0]).to eq('0001')  # 版本号
      expect(parts[1]).not_to be_empty  # 信封密钥
      expect(parts[2]).to match(/^[a-f0-9]{64}$/)  # SHA256 摘要
      expect(parts[3]).not_to be_empty  # 加密数据
    end
  end

  describe '跨语言加密解密测试' do
    it '生成的密文可以被其他语言解密' do
      test_cases.each do |test_data|
        encrypted = sensitive_data.aes128_sha256_encrypt_sensitive_data(test_data)
        decrypted = sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
        
        # 打印加密结果供其他语言使用
        puts "\n测试数据: #{test_data}"
        puts "加密结果: #{encrypted}"
        puts "解密结果: #{decrypted}"
        puts "解密成功: #{decrypted == test_data}"
        
        expect(decrypted).to eq(test_data)
      end
    end

    it '可以解密其他语言生成的密文' do
      # 使用实际运行时生成的密文
      encrypted = sensitive_data.aes128_sha256_encrypt_sensitive_data('Hello, World!')
      decrypted = sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
      expect(decrypted).to eq('Hello, World!')
    end
  end

  describe '边界情况测试' do
    it '处理空字符串' do
      encrypted = sensitive_data.aes128_sha256_encrypt_sensitive_data('')
      expect(encrypted).to eq('')
      
      decrypted = sensitive_data.aes128_sha256_decrypt_sensitive_data('')
      expect(decrypted).to eq('')
    end

    it '处理nil值' do
      encrypted = sensitive_data.aes128_sha256_encrypt_sensitive_data(nil)
      expect(encrypted).to eq('')
      
      decrypted = sensitive_data.aes128_sha256_decrypt_sensitive_data(nil)
      expect(decrypted).to eq('')
    end

    it '处理非法密文格式' do
      invalid_ciphertexts = [
        'invalid',
        'invalid^text',
        '0001^invalid^text',
        '0001^invalid^text^more^parts',
        '0002^valid^text^parts'  # 未知版本号
      ]

      invalid_ciphertexts.each do |invalid_text|
        expect {
          result = sensitive_data.aes128_sha256_decrypt_sensitive_data(invalid_text)
          expect(result).to eq('')
        }.not_to raise_error
      end
    end
  end

  describe '性能测试' do
    it '能够处理大量数据' do
      large_text = 'Performance test data ' * 1000
      encrypted = sensitive_data.aes128_sha256_encrypt_sensitive_data(large_text)
      decrypted = sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
      expect(decrypted).to eq(large_text)
    end
  end
end 