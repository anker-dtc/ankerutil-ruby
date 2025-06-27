require 'openssl'
require 'base64'
require 'securerandom'

module AnkerUtil
  class SensitiveData
    CONSTANTS = {
      SENSITIVE_DATA_KEY_LEN: 64,
      SENSITIVE_ROOT_KEY_LEN: 32,
      SENSITIVE_ROOT_KEY_VERSION_LEN: 4,
      DEFAULT_ROOT_KEY_VERSION: '0001',
      NEW_CIPHERTEXT_SPLIT_LEN: 4,
      OLD_CIPHERTEXT_SPLIT_LEN: 2,
      AES_BLOCK_SIZE: 16
    }.freeze

    attr_reader :sensitive_data_key, :sensitive_root_key, :sensitive_root_key_version, :sensitive_root_key_value

    def initialize
      @sensitive_data_key = nil
      @sensitive_root_key = {}
      @sensitive_root_key_version = nil
      @sensitive_root_key_value = nil
    end

    # 初始化密钥
    def init_sensitive_key(cbc_key, root_key)
      # 验证 cbc_key
      raise 'InitSensitiveKey cbcKey len invalid' unless cbc_key.length == CONSTANTS[:SENSITIVE_DATA_KEY_LEN]
      
      key_bytes = [cbc_key].pack('H*')
      raise 'InitSensitiveKey cbcKey BlockSize error' unless key_bytes.length == 2 * CONSTANTS[:AES_BLOCK_SIZE]

      @sensitive_data_key = cbc_key

      # 验证 root_key
      raise 'InitSensitiveKey rootKey not empty' if root_key.nil? || root_key.empty?

      root_key.each do |version, key|
        raise 'InitSensitiveKey rootKeyVersion len invalid' unless version.length == CONSTANTS[:SENSITIVE_ROOT_KEY_VERSION_LEN]
        raise 'InitSensitiveKey rootKey len invalid' unless key.length == CONSTANTS[:SENSITIVE_ROOT_KEY_LEN]

        key_bytes = [key].pack('H*')
        raise 'InitSensitiveKey rootKey BlockSize error' unless key_bytes.length == CONSTANTS[:AES_BLOCK_SIZE]

        @sensitive_root_key[version] = key
      end

      # 设置最新版本的 root_key
      versions = @sensitive_root_key.keys.sort
      unless versions.empty?
        @sensitive_root_key_version = versions.last
        @sensitive_root_key_value = @sensitive_root_key[@sensitive_root_key_version]
      end
    end

    # AES-CBC 加密
    def aes_cbc_encrypt(plaintext, key)
      return plaintext if plaintext.nil? || plaintext.empty?
      
      key_bytes = [key].pack('H*')
      iv = SecureRandom.random_bytes(CONSTANTS[:AES_BLOCK_SIZE])
      
      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.encrypt
      cipher.key = key_bytes
      cipher.iv = iv
      cipher.padding = 1  # PKCS5 padding

      # 确保输入是二进制编码
      binary_plaintext = plaintext.to_s.dup.force_encoding('BINARY')
      encrypted = cipher.update(binary_plaintext) + cipher.final
      
      # 组合IV和密文，然后Base64编码
      Base64.strict_encode64(iv + encrypted)
    rescue => e
      raise "AES CBC Encryption failed: #{e.message}"
    end

    # AES-CBC 解密
    def aes_cbc_decrypt(ciphertext, key)
      return ciphertext if ciphertext.nil? || ciphertext.empty?
      
      begin
        key_bytes = [key].pack('H*')
        data = Base64.strict_decode64(ciphertext)
        
        # 提取IV和密文
        iv = data[0, CONSTANTS[:AES_BLOCK_SIZE]]
        encrypted_data = data[CONSTANTS[:AES_BLOCK_SIZE]..-1]
        
        decipher = OpenSSL::Cipher.new('AES-128-CBC')
        decipher.decrypt
        decipher.key = key_bytes
        decipher.iv = iv
        decipher.padding = 1  # PKCS5 padding
        
        result = decipher.update(encrypted_data) + decipher.final
        # 转换为UTF-8编码
        result.force_encoding('UTF-8')
      rescue => e
        ciphertext
      end
    end

    # SHA256 哈希
    def sha256(text)
      # 确保输入是UTF-8编码
      utf8_text = text.to_s.encode('UTF-8')
      OpenSSL::Digest::SHA256.hexdigest(utf8_text)
    end

    # 生成随机AES密钥
    def generate_aes_key
      SecureRandom.hex(16)
    end

    # AES128+SHA256 加密敏感数据
    def aes128_sha256_encrypt_sensitive_data(plaintext)
      return plaintext if plaintext.nil? || plaintext.empty?

      begin
        # 确保输入是UTF-8编码
        utf8_plaintext = plaintext.to_s.encode('UTF-8')
        digest = sha256(utf8_plaintext)
        data_key = generate_aes_key
        secret_data = aes_cbc_encrypt(utf8_plaintext, data_key)
        envelope_key = aes_cbc_encrypt(data_key, @sensitive_root_key_value)

        "#{@sensitive_root_key_version}^#{envelope_key}^#{digest}^#{secret_data}"
      rescue => e
        plaintext  # 加密失败时返回空字符串
      end
    end

    # AES128+SHA256 解密敏感数据
    def aes128_sha256_decrypt_sensitive_data(ciphertext)
      return ciphertext if ciphertext.nil? || ciphertext.empty?

      begin
        parts = ciphertext.split('^')

        # 处理新版加密数据
        if parts.length == CONSTANTS[:NEW_CIPHERTEXT_SPLIT_LEN]
          root_key_version, envelope_key, digest, secret_data = parts

          return ciphertext if [root_key_version, envelope_key, digest, secret_data].any?(&:nil?)

          root_key = @sensitive_root_key[root_key_version]
          return ciphertext unless root_key  # 如果找不到对应版本的root_key，返回空字符串

          data_key = aes_cbc_decrypt(envelope_key, root_key)
          return ciphertext if data_key.empty?

          plaintext = aes_cbc_decrypt(secret_data, data_key)
          return ciphertext if plaintext.empty?

          # 验证摘要时确保使用UTF-8编码
          return ciphertext unless sha256(plaintext) == digest

          # 确保返回UTF-8编码的字符串
          plaintext.encode('UTF-8')
        else
          # 处理旧版加密数据
          decrypt_sensitive_data_by_data_key(ciphertext)
        end
      rescue => e
        ciphertext  # 解密失败时返回原值
      end
    end

    # 处理旧版加密数据
    def decrypt_sensitive_data_by_data_key(ciphertext)
      begin
        parts = ciphertext.split('^')
        return ciphertext unless parts.length == CONSTANTS[:OLD_CIPHERTEXT_SPLIT_LEN]

        root_key_version, secret_data = parts
        return ciphertext unless root_key_version == CONSTANTS[:DEFAULT_ROOT_KEY_VERSION] && !secret_data.empty?

        result = aes_cbc_decrypt(secret_data, @sensitive_data_key)
        result.encode('UTF-8')
      rescue => e
        ciphertext  # 解密失败时返回原值
      end
    end

    # 小写转换后加密
    def lower_aes128_sha256_encrypt_sensitive_data(plaintext)
      return plaintext if plaintext.nil? || plaintext.empty?
      aes128_sha256_encrypt_sensitive_data(plaintext.to_s.downcase)
    end
  end
end 