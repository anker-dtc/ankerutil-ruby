require 'spec_helper'
require_relative '../lib/sensitive_data'

RSpec.describe Ankerutil::Encrypt::Sensitive::SensitiveData do
  before(:all) do
    @sensitive_data = described_class.new
    # 初始化加密密钥
    cbc_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    root_key = {
      "0001" => "0123456789abcdef0123456789abcdef"
    }
    @sensitive_data.init_sensitive_key(cbc_key, root_key)
  end

  describe '#aes128_sha256_decrypt_sensitive_data' do
    it 'should correctly decrypt empty string' do
      expect(@sensitive_data.aes128_sha256_decrypt_sensitive_data('')).to eq('')
    end

    it 'should correctly decrypt newline' do
      encrypted = '0001^43ZKRv9qeDuQfn9Osaa5jOaOjDarCOR0irf0b7a+Neuuc2ISpZAGXGtiBBbusxjwHkgJ0EpPXWeqTQZnM/24Ug==^01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b^tFCfisC6ZSxqMiAqwUps9ZLIabVD3hgxVpjCYqnfedQ='
      expect(@sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)).to eq("\n")
    end

    it 'should correctly decrypt tab' do
      encrypted = '0001^1bZegEKH5PEKEmpZ/xbbn0FcwXnougiQgVvPtN2H1ZtX13MXpIlOnUhYCzgwRraxBTmKyhBAZ4cN4iRJmsWv1Q==^2b4c342f5433ebe591a1da77e013d1b72475562d48578dca8b84bac6651c3cb9^jDddN9UIB5cTkVs8zHj2NTcsAu6WqyLs6NveyoSG+bA='
      expect(@sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)).to eq("\t")
    end

    it 'should correctly decrypt Chinese text' do
      encrypted = '0001^eA7RoO08Laew/+NsViEAQ9XCpYH3+KUyiie/Sm1QIu6/+IJWtoIA0Gl7UXdArdTDLK1+RsQIU4ZsoAXW/Tq8IQ==^cd78f6be8972066d2c4eb873fcfe87be7edb8bdf918b83bec09a47e7ed255f36^aFLecSb6NuJjj+fpR6fs5pQEI+9p1KPPMF/Wsh4k6w+A3zXwbUAFQs7oddSSDFa+'
      expect(@sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)).to eq("这是中文测试")
    end

    it 'should correctly decrypt Japanese text' do
      encrypted = '0001^oJKIrrIHYSWnv00ipCb9E1K94g6P06KfutrPKzLmmw2mGvC4p16DymLxpUrUkV0ZZjEIcdxyyJRrKXZKl1GZTA==^3a57bd94b9bcda801052f149337366d3ec00555c67efaf5d355c80d347678061^OeYz+rsHmuBHzxG8YdvSt3us3YM3EVjsZtiAYXWhl4Y8BMudOOIWxnQj5LVTkzWj'
      expect(@sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)).to eq("これは日本語です")
    end

    it 'should correctly decrypt JSON string' do
      encrypted = '0001^JZC9vHiiDtPAMZf/9XW9NOkgyuxu0xDkSRc+mYkHAtDKKzKeGxBLs8eeATSZ+XBBOE64OKokmM0VY6Cp2QUAfA==^4fc0f4fa0d02ef6da9bdd535857bb258856e3547cbf9cbfc07d33424ac8757b3^LLHe21lfhIz4z3Pe/BqjftrHekz/LKiLmXUxqsU0JZrlBO2EcyFlpoem8zZsdZ1/wJtYq3OsJaQXBI8rXRcDEg=='
      expect(@sensitive_data.aes128_sha256_decrypt_sensitive_data(encrypted)).to eq('{"key": "value", "chinese": "中文"}')
    end
  end
end 

'/Users/anker/demo/ankerutil-ruby/lib/sensitive_data.rb'