module AnkerUtil
  class NacosClient
    def initialize(host, username, password)
      @host = host
      @username = username 
      @password = password
      @access_token = nil
    end

    def login
      response = Faraday.post("#{@host}/nacos/v1/auth/login", {
        username: @username,
        password: @password
      })
      data = JSON.parse(response.body)
      @access_token = data['accessToken']
      data
    rescue => e
      Rails.logger.error "Nacos登录失败: #{e.message}"
      nil
    end

    def get_config(data_id, group, tenant = nil)
      login if @access_token.nil?

      response = Faraday.get("#{@host}/nacos/v1/cs/configs") do |req|
        params = {
          dataId: data_id,
          group: group,
          accessToken: @access_token
        }
        params[:tenant] = tenant if tenant.present?
        req.params = params
      end
      
      JSON.parse(response.body)
    rescue => e
      Rails.logger.error "获取Nacos配置失败: #{e.message}"
      nil
    end
  end
end
