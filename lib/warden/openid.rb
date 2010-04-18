require 'warden'
require 'rack/openid'

module Warden
  module OpenID
    def self.user_finder(&block)
      block ? @@_user_finder = block : @@_user_finder
    end

    class Strategy < Warden::Strategies::Base
      def authenticate!
        if response = env[Rack::OpenID::RESPONSE]
          case response.status
          when :success
            if user = Warden::OpenID.user_finder.call(response)
              success!(user)
            else
              fail!('User not found')
              throw(:warden, :openid => {:response => response})
            end
          else
            fail!(response.respond_to?(:message) ? response.message : "OpenID authentication failed: #{response.status}")
          end
        elsif identifier = params['openid_identifier']
          if identifier.empty?
            fail!('OpenID identifier is required')
          else
            custom!([401, {'WWW-Authenticate' => Rack::OpenID.build_header(:identifier => identifier)}, ''])
          end
        end
      end
    end
  end
end
