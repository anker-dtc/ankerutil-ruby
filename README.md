# AnkerUtil-Ruby

Ruby 敏感数据加密工具库，提供 AES-128-CBC + SHA256 混合加密方案，支持多版本根密钥管理。

## 功能特性

- 混合加密方案：AES-128-CBC 数据加密 + SHA256 摘要验证
- 多版本根密钥支持：支持密钥版本管理和轮换
- 跨语言兼容：与 Go/Node.js 版本保持算法兼容性
- 自动处理 Ruby 字符串编码问题
- 支持 MRI 和 JRuby 运行环境
- 完整的 RSpec 测试套件
- 兼容 Ruby 2.5+ 版本

## 安装

在 Gemfile 中添加：```ruby
gem 'ankerutil-ruby', path: '/path/to/ankerutil-ruby'
```

## 主要功能

### 1. 敏感数据加密
```ruby
# 初始化密钥
cbc_key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
root_key = { 
  '0001' => '0123456789abcdef0123456789abcdef',  # 当前版本根密钥
  '0002' => 'abcdef0123456789abcdef0123456789'   # 历史版本根密钥
}

handler = AnkerUtil::SensitiveData.new
handler.init_sensitive_key(cbc_key, root_key)

# 加密/解密
encrypted = handler.encrypt_sensitive_data('Hello World')
decrypted = handler.decrypt_sensitive_data(encrypted)
```

### 2. 编码处理
- 自动处理 Ruby 字符串编码
- 支持 UTF-8 和其他编码格式
- 处理特殊字符和转义序列

## 使用示例

```ruby
require 'ankerutil-ruby'

# 初始化密钥（使用预生成密钥）
cbc_key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
root_key = { 
  '0001' => '0123456789abcdef0123456789abcdef',  # 当前版本根密钥
  '0002' => 'abcdef0123456789abcdef0123456789'   # 历史版本根密钥
}

handler = AnkerUtil::SensitiveData.new
handler.init_sensitive_key(cbc_key, root_key)

# 加密/解密
encrypted = handler.encrypt_sensitive_data('Hello World')
decrypted = handler.decrypt_sensitive_data(encrypted)
puts decrypted # 输出: Hello World
```

## 测试
```bash
bundle install
bundle exec rspec
```

## 许可证
MIT
