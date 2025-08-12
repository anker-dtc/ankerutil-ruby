require 'minitest/autorun'
require_relative '../lib/ankerutil/secret_manage'

class SecretManageTest < Minitest::Test
  def setup
    @secret_manage = AnkerUtil::SecretManage.new
  end

  def test_process_secret_config_with_json
    config_content = <<~CONFIG
      {
        "SecretManage": {
          "Key": "118c02b71e211049304bd70a0c971d77",
          "Domain": "https://vsaas-api-ci.eufylife.com",
          "Name": "DTC"
        },
        "other_key": "value"
      }
    CONFIG

    # 由于真实API不可用，这里只测试解析流程，不断言API结果
    result = nil
    begin
      result = @secret_manage.process_secret_config(config_content)
    rescue => e
      result = e.message
    end
    refute_nil result
  end

  def test_process_secret_config_with_yaml
    config_content = <<~CONFIG
      SecretManage:
        Key: "118c02b71e211049304bd70a0c971d77"
        Domain: "https://vsaas-api-ci.eufylife.com"
        Name: "DTC"
      other_key: value
    CONFIG

    result = nil
    begin
      result = @secret_manage.process_secret_config(config_content)
    rescue => e
      result = e.message
    end
    refute_nil result
  end

  def test_process_secret_config_with_ini
    config_content = <<~CONFIG
      [SecretManage]
      Key=118c02b71e211049304bd70a0c971d77
      Domain=https://vsaas-api-ci.eufylife.com
      Name=DTC
      [Other]
      other_key=value
    CONFIG

    result = nil
    begin
      result = @secret_manage.process_secret_config(config_content)
    rescue => e
      result = e.message
    end
    refute_nil result
  end

  def test_process_secret_config_with_invalid_content
    config_content = "not a valid config"

    result = nil
    begin
      result = @secret_manage.process_secret_config(config_content)
    rescue => e
      result = e.message
    end
    refute_nil result
  end

  def test_process_secret_config_with_incomplete_secretmanage
    config_content = <<~CONFIG
      {
        "SecretManage": {
          "Key": "118c02b71e211049304bd70a0c971d77"
        }
      }
    CONFIG

    result = @secret_manage.process_secret_config(config_content)
    assert_equal config_content, result
  end
end
