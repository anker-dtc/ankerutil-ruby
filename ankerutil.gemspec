# frozen_string_literal: true

require_relative "lib/ankerutil/version"

Gem::Specification.new do |spec|
  spec.name = "ankerutil"
  spec.version = AnkerUtil::VERSION
  spec.authors = ["AnkerUtil Team"]
  spec.email = ["dev@anker.com"]

  spec.summary = "Ruby 敏感数据加密工具库，提供 AES-128-CBC + SHA256 混合加密方案"
  spec.description = "Ruby 敏感数据加密工具库，提供 AES-128-CBC + SHA256 混合加密方案，支持多版本根密钥管理。支持跨语言兼容，自动处理 Ruby 字符串编码问题。"
  spec.homepage = "https://github.com/anker/ankerutil-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.5.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # 指定需要包含在 gem 中的文件
  spec.files = Dir.glob("{bin,lib}/**/*") + %w[README.md LICENSE.txt CHANGELOG.md]
  spec.require_paths = ["lib"]

  # 开发依赖
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rubocop", "~> 1.0"
end 