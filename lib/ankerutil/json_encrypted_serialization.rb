module AnkerUtil
  class JsonEncryptedSerialization
    # 定义需要加密的 JSON 字段名
    JSON_FIELD_NAMES = %w[address1 address2 zip phone name first_name last_name company
      latitude longitude email].freeze
  
    # 基于 ActiveModel::Type::Value 实现更优， rails 官方的加密就是这样实现的，但是订阅中心的 rails 4 版本不支持
    class << self
      def init_sensitive_key(cbc_key, root_key, disable_write=false)
        @sensitive_data = SensitiveData.new
        @disable_write = disable_write
        @sensitive_data.init_sensitive_key(cbc_key, root_key)
      end

      def sensitive_data
        raise '请先调用 init_sensitive_key 初始化密钥' if @sensitive_data.nil?
        @sensitive_data
      end
    
      def load(value)
        return value if value.blank?
      
        decrypt_json_fields(value)
      end
    
      def dump(value)
        return value if value.blank? || @disable_write || is_encrypted?(value)
      
        encrypt_json_fields(value)
      end
    
      def is_encrypted?(value)
        return false if value.blank?
      
        value.to_s.split('^').size == 4
      end
    
      private
    
      def encrypt_json_fields(data)
        case data
        when Hash
          result = {}
          data.each do |k, v|
            result[k] = if JSON_FIELD_NAMES.include?(k.to_s.downcase)
                          is_encrypted?(v) ? v : sensitive_data.aes128_sha256_encrypt_sensitive_data(v.to_s)
                        else
                          encrypt_json_fields(v)
                        end
          end
          result
        when Array
          data.map { |item| encrypt_json_fields(item) }
        else
          data
        end
      end
    
      def decrypt_json_fields(data)
        case data
        when Hash
          result = {}
          data.each do |k, v|
            result[k] = if JSON_FIELD_NAMES.include?(k.to_s.downcase)
                          !is_encrypted?(v) ? v : sensitive_data.aes128_sha256_decrypt_sensitive_data(v.to_s)
                        else
                          decrypt_json_fields(v)
                        end
          end
          result
        when Array
          data.map { |item| decrypt_json_fields(item) }
        else
          data
        end
      end
    end
  end
end