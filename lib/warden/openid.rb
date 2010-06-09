require 'warden'
require 'rack/openid'

module Warden
  module OpenID
    CONFIG_EXAMPLE = <<-CODE
Warden::OpenID.configure do |config|
  config.user_finder do |response|
    # do something
  end
end
    CODE

    class Config
      attr_accessor :required_fields, :optional_fields, :policy_url

      def user_finder(&block)
        @user_finder = block
      end

      def find_user(response)
        raise "Warden::OpenID::Config#user_finder has not been set yet.\n\n#{Warden::OpenID::CONFIG_EXAMPLE}" unless @user_finder
        @user_finder.call(response)
      end

      def to_params
        {
          :required   => required_fields,
          :optional   => optional_fields,
          :policy_url => policy_url
        }
      end
    end

    class << self
      def config
        @@config ||= Config.new
      end

      def configure(&block)
        block.call(config)
      end

      def user_finder(&block)
        $stderr.puts "DEPRECATION WARNING: Warden::OpenID.user_finder is deprecated. Use Warden::OpenID::Config#user_finder instead.\n\n#{CONFIG_EXAMPLE}"

        configure do |config|
          config.user_finder(&block)
        end
      end
    end

    class Strategy < Warden::Strategies::Base
      def authenticate!
        if response = env[Rack::OpenID::RESPONSE]
          case response.status
          when :success
            if user = Warden::OpenID.config.find_user(response)
              success!(user)
            else
              fail!('User not found')
              throw(:warden, :openid => {:response => response})
            end
          else
            fail!(response.respond_to?(:message) ? response.message : "OpenID authentication failed: #{response.status}")
          end
        elsif identifier = params['openid_identifier']
          if identifier.nil? || identifier.empty?
            fail!('OpenID identifier is required')
          else
             custom!([401, {'WWW-Authenticate' => Rack::OpenID.build_header(Warden::OpenID.config.to_params.merge(:identifier => identifier))}, ''])
          end
        end
      end
    end
  end
end
