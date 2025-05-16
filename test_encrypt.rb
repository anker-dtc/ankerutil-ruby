require_relative 'lib/ankerutil'

# 创建实例
sensitive_data = Ankerutil::SensitiveData.new

# 初始化密钥
cbc_key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
root_key = {
  '0001' => '0123456789abcdef0123456789abcdef'
}

sensitive_data.init_sensitive_key(cbc_key, root_key)

# 测试数据
plaintext = 'Hello, World!'

# 加密
encrypted = sensitive_data.aes128_sha256_encrypt_sensitive_data(plaintext)

puts "原文: #{plaintext}"
puts "密文: #{encrypted}"

# 解密
decrypted = sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)

puts "解密后: #{decrypted}"
puts "解密成功: #{decrypted == plaintext}"

# 测试解密Go生成的密文
go_encrypted = '0001^wKOCCRx4+rg2SEdxXXxXUvppZGv8v7cfCn05fK+IofGM73bHwEvZG235ocHfsA64XhUnIzgQqLWRkmmr3YfKfw==^dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f^x1QVsjF9cL09/Fog3Jnbth0+SJgZ87AaAqSdItkt13M='

puts "\n测试解密Go生成的密文:"
decrypted_go = sensitive_data.aes128_sha256_decrypt_sensitive_data(go_encrypted)
puts "Go密文解密后: #{decrypted_go}"
puts "解密成功: #{decrypted_go == plaintext}" 