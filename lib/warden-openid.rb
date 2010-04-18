require 'warden/openid'

Warden::Strategies.add :openid, Warden::OpenID::Strategy
