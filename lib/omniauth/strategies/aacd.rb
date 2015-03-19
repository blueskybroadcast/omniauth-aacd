require 'omniauth-oauth2'
require 'rest_client'

module OmniAuth
  module Strategies
    class Aacd < OmniAuth::Strategies::OAuth2
      option :name, 'aacd'

      option :client_options, {
        site: 'http://www.aacd.com',
        user_info_url: '/wsAPI.php',
        authorize_url: '/index.php?module=aacd.websiteforms&cmd=bluesky',
        username: 'MUST BE SET',
        password: 'MUST BE SET'
      }

      uid { raw_info[:id] }

      info do
        {
          first_name: raw_info[:first_name],
          last_name: raw_info[:last_name],
          email: raw_info[:email],
          imis_id: uid,
          member_level: raw_info[:member_level]
        }
      end

      extra do
        { :raw_info => raw_info }
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//,"")
        redirect authorize_url + "&redirectURL=" + callback_url + "?slug=#{slug}"
      end

      def callback_phase
        self.access_token = {
          :token =>  request.params['token'],
          :token_expires => 60
        }
        self.env['omniauth.auth'] = auth_hash
        call_app!
      end

      def creds
        self.access_token
      end

      def auth_hash
        hash = AuthHash.new(:provider => name, :uid => uid)
        hash.info = info
        hash.credentials = creds
        hash.extra = extra
        hash
      end

      def raw_info
        @raw_info ||= get_user_info
      end

      def get_user_info
        response = RestClient.get(user_info_url,
          { params:
            { 'module' => module_name,
              'method' => method_lookup,
              'username' => options.client_options.username,
              'password' => options.client_options.password,
              'token' => access_token[:token]
            }
          }
        )

        parsed_response = JSON.parse(response)

        if parsed_response['message'] == 'Success'
          info = {
            id: parsed_response['data']['IMIS'],
            first_name: parsed_response['data']['FirstName'],
            last_name: parsed_response['data']['LastName'],
            email: parsed_response['data']['Email'],
            member_level: parsed_response['data']['MemberLevel']
          }
        else
          nil
        end
      end

      private

      def authentication_token
        options.client_options.authentication_token
      end

      def authorize_url
        "#{options.client_options.site}#{options.client_options.authorize_url}"
      end

      def method_lookup
        'blueSkyLookup'
      end

      def module_name
        'aacd.websiteforms'
      end

      def user_info_url
        "#{options.client_options.site}#{options.client_options.user_info_url}"
      end
    end
  end
end

