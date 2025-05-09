# AnkerUtil-Ruby

Ruby 敏感数据加密工具库，与 Node.js/Go 实现保持算法兼容性，提供 AES-128-CBC + SHA256 混合加密方案。

## 功能特性

- 与 Node.js/Go 版本的密文互操作性
- 自动处理 Ruby 字符串编码问题
- 支持 MRI 和 JRuby 运行环境
- 提供 RSpec 测试套件
- 兼容 Ruby 2.5+ 版本

## 安装

在 Gemfile 中添加：
```ruby
gem 'ankerutil-ruby', path: '/path/to/ankerutil-ruby'
```

## 测试
```bash
bundle install
bundle exec rspec
```

## 用法
```ruby
require 'ankerutil-ruby'

# 初始化密钥（直接使用预生成密钥）
cbc_key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
root_key = { 
  '0001' => '0123456789abcdef0123456789abcdef',  # 当前版本根密钥
  '0002' => 'abcdef0123456789abcdef0123456789'   # 历史版本根密钥（兼容旧数据）
}

handler = SensitiveData.new
handler.init_sensitive_key(cbc_key, root_key)

# 加密/解密
encrypted = handler.encrypt_sensitive_data('Hello World')
decrypted = handler.decrypt_sensitive_data(encrypted)
```

## 许可证
MIT