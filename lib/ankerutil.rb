module AnkerUtil
  require_relative 'ankerutil/nacos_client'
  require_relative 'ankerutil/sensitive_data'
  require_relative 'ankerutil/string_encrypted_serialization'
  require_relative 'ankerutil/json_encrypted_serialization'

  def self.init_sensitive_key(cbc_key, root_key)
    StringEncryptedSerialization.init_sensitive_key(cbc_key, root_key)
    JSONEncryptedSerialization.init_sensitive_key(cbc_key, root_key)
  end
end