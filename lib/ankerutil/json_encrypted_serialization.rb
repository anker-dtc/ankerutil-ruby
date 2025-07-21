module AnkerUtil
  class JsonEncryptedSerialization
    # 定义需要加密的 JSON 字段名
    JSON_FIELD_NAMES = %w[address1 address2 zip phone name first_name last_name company
      latitude longitude email company_name
      caller_name caller_phone recipient_name recipient_phone call_details
      buyer_name buyer_email buyer_phone_number buyer_postal_code
      ship_address_1 ship_address_2 ship_postal_code ship_phone_number].freeze
  
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
        return value if value.nil?
      
        decrypt_json_fields(value)
      end
    
      def dump(value)
        return value if value.nil? || @disable_write || is_encrypted?(value)
      
        encrypt_json_fields(value)
      end
    
      def is_encrypted?(value)
        return false if value.nil?
      
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