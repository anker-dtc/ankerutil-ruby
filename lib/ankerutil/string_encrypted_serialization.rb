module AnkerUtil
class StringEncryptedSerialization
  # 基于 ActiveModel::Type::Value 实现更优， rails 官方的加密就是这样实现的，但是订阅中心的 rails 4 版本不支持
  class << self
    def init_sensitive_key(cbc_key, root_key)
      @sensitive_data = SensitiveData.new
      @sensitive_data.init_sensitive_key(cbc_key, root_key)
    end

    def sensitive_data
      raise '请先调用 init_sensitive_key 初始化密钥' if @sensitive_data.nil?
      @sensitive_data
    end

    def load(value)
      return value if value.blank? || !is_encrypted?(value)

      sensitive_data.aes128_sha256_decrypt_sensitive_data(value.to_s)
    end

    def dump(value)
      return value if value.blank? || is_encrypted?(value)

      sensitive_data.aes128_sha256_encrypt_sensitive_data(value.to_s)
    end

    def is_encrypted?(value)
      return false if value.blank?

      value.split('^').size == 4
    end
  end
end

end