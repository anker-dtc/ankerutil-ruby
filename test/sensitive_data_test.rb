require 'rspec'
require_relative '../lib/encrypt/sensitive/sensitive_data'

RSpec.describe Ankerutil::Encrypt::Sensitive::SensitiveData do
  let(:sensitive_data) { described_class.new }
  let(:cbc_key) { '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' }
  let(:root_key) { { '0001' => '0123456789abcdef0123456789abcdef' } }
  let(:test_data) { 'Hello, World!' }

  before do
    sensitive_data.init_sensitive_key(cbc_key, root_key)
  end

  describe '初始化' do
    it '正确初始化密钥' do
      expect(sensitive_data.sensitive_data_key).to eq(cbc_key)
      expect(sensitive_data.sensitive_root_key['0001']).to eq(root_key['0001'])
      expect(sensitive_data.sensitive_root_key_version).to eq('0001')
      expect(sensitive_data.sensitive_root_key_value).to eq(root_key['0001'])
    end
  end

  describe '加密解密' do
    it '可以加密并解密数据' do
      encrypted = sensitive_data.aes128_sha256_encrypt_sensitive_data(test_data)
      decrypted = sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
      
      puts "原文: #{test_data}"
      puts "密文: #{encrypted}"
      puts "解密后: #{decrypted}"
      puts "解密成功: #{decrypted == test_data}"
      
      expect(decrypted).to eq(test_data)
    end

    it '可以解密Go生成的密文' do
      # Go生成的密文
      go_encrypted = '0001^wKOCCRx4+rg2SEdxXXxXUvppZGv8v7cfCn05fK+IofGM73bHwEvZG235ocHfsA64XhUnIzgQqLWRkmmr3YfKfw==^dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f^x1QVsjF9cL09/Fog3Jnbth0+SJgZ87AaAqSdItkt13M='
      
      decrypted = sensitive_data.aes128_sha256_decrypt_sensitive_data(go_encrypted)
      expect(decrypted).to eq(test_data)
    end

    it '处理空输入' do
      expect(sensitive_data.aes128_sha256_encrypt_sensitive_data('')).to eq('')
      expect(sensitive_data.aes128_sha256_decrypt_sensitive_data('')).to eq('')
    end

    it '支持小写转换加密' do
      test_data = 'Hello, World!'
      encrypted = sensitive_data.lower_aes128_sha256_encrypt_sensitive_data(test_data)
      decrypted = sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)
      expect(decrypted).to eq(test_data.downcase)
    end
  end
end 