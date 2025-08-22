require 'json'
require 'yaml'
require 'net/http'
require 'uri'
require 'openssl'
require 'time'
require 'logger'

module AnkerUtil
  class SecretManage
    # https://anker-in.feishu.cn/wiki/RSZuwq4hBizj7wksrR3cPGIAnsh
    attr_accessor :logger

    def initialize
      @logger = Logger.new(STDOUT)
      @logger.level = Logger::INFO
    end

    # 处理敏感配置，解析配置并调用敏感配置服务
    # 支持 JSON, YAML 和 INI 三种格式的配置
    # 1. 先尝试 JSON 解析
    # 2. 如果 JSON 解析失败，再尝试使用简单方法解析 YAML/INI
    # 3. 提取所需的 SecretManage 配置信息
    # 4. 调用 API 处理敏感配置
    # 返回处理后的内容，或者空字符串和错误
    def process_secret_config(content)
      # 定义一个通用的 hash 来存储配置
      config_map = {}

      # 先尝试 JSON 格式解析
      begin
        config_map = JSON.parse(content)
      rescue JSON::ParserError => e
        @logger.info("JSON parse failed: #{e.message}, trying to parse as YAML")
        
        # 尝试 YAML 解析
        begin
          config_map = YAML.load(content)
        rescue Psych::SyntaxError => e
          @logger.info("YAML parse failed: #{e.message}")
          
          # 尝试 INI 格式解析（简化版本）
          begin
            config_map = parse_ini_content(content)
          rescue => e
            @logger.error("INI parse failed: #{e.message}")
            raise "Failed to parse config: #{e.message}"
          end
        end
      end

      # 提取 SecretManage 配置
      secret_config = extract_secret_manage_config(config_map)
      
      if secret_config[:name].nil? || secret_config[:key].nil? || secret_config[:domain].nil?
        @logger.info("SecretManage config is not complete: #{secret_config.inspect}, return origin content")
        return content
      end

      # 请求敏感管理服务器，直接传递原始内容
      begin
        decrypted_value = call_secret_manage_api(content, secret_config)
        @logger.info("Successfully processed secret config")
        return decrypted_value
      rescue => e
        @logger.error("Call SecretManage API failed: #{e.message} #{content}")
        raise e
      end
    end

    private

    # 解析 INI 格式内容
    def parse_ini_content(content)
      config = {}
      current_section = 'default'
      
      content.each_line do |line|
        line.strip!
        next if line.empty? || line.start_with?('#')
        
        if line.start_with?('[') && line.end_with?(']')
          current_section = line[1..-2]
          config[current_section] ||= {}
        elsif line.include?('=')
          key, value = line.split('=', 2)
          config[current_section] ||= {}
          config[current_section][key.strip] = value.strip
        end
      end
      
      # 转换为统一格式
      {
        'SecretManage' => {
          'Key' => config.dig('default', 'SecretManage.Key'),
          'Domain' => config.dig('default', 'SecretManage.Domain'),
          'Name' => config.dig('default', 'SecretManage.Name')
        }
      }
    end

    # 提取 SecretManage 配置信息
    def extract_secret_manage_config(config_map)
      secret_manage = config_map['SecretManage'] || {}
      
      {
        key: secret_manage['Key'] || config_map['SecretManage.Key'],
        domain: secret_manage['Domain'] || config_map['SecretManage.Domain'],
        name: secret_manage['Name'] || config_map['SecretManage.Name']
      }
    end

    # 调用敏感配置管理API
    def call_secret_manage_api(content, secret_conf)
      # 1. 准备请求参数
      timestamp = Time.now.to_i

      # 2. 生成签名
      message = "SecretManageAnker+#{timestamp}+#{secret_conf[:name]}+#{secret_conf[:key]}"
      signature = OpenSSL::HMAC.hexdigest('sha256', secret_conf[:key], message)

      # 3. 构造请求体
      req_body = {
        auth: {
          system_name: secret_conf[:name],
          timestamp: timestamp,
          signature: signature
        },
        config: content
      }

      # 4. 发送HTTP请求
      url = "#{secret_conf[:domain]}/secretmanage/decrypt/config"
      uri = URI(url)
      
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      http.open_timeout = 10
      http.read_timeout = 10

      request = Net::HTTP::Post.new(uri)
      request['Content-Type'] = 'application/json'
      request.body = req_body.to_json

      response = http.request(request)

      # 5. 解析响应
      unless response.is_a?(Net::HTTPSuccess)
        raise "HTTP request failed with status #{response.code}: #{response.body}"
      end

      response_data = JSON.parse(response.body)
      
      if response_data['code'] != 0
        raise "API returned error: #{response_data['msg']}"
      end

      # 检查返回数据中是否包含config字段
      if response_data['data'].nil?
        raise "Response data is empty"
      end

      config_value = response_data['data']['config']
      if config_value.nil?
        raise "Response data does not contain 'config' field"
      end

      config_value
    end
  end

  # 使用示例
  if __FILE__ == $0
    secret_manage = SecretManage.new
    
    # 示例配置内容
    config_content = <<~CONFIG
      {
       "SecretManage": {
        "Key": "118c02b71e211049304bd70a0c971d77",
        "Domain": "https://vsaas-api-ci.eufylife.com",
        "Name": "DTC"
        }
      }
    CONFIG
    
    begin
      result = secret_manage.process_secret_config(config_content)
      puts "处理结果: #{result}"
    rescue => e
      puts "错误: #{e.message}"
    end
  end
end
