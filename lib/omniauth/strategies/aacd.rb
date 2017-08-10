require 'omniauth-oauth2'
require 'rest_client'

module OmniAuth
  module Strategies
    class Aacd < OmniAuth::Strategies::OAuth2
      option :name, 'aacd'

      option :app_options, { app_event_id: nil }

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
        slug = request.params['slug']
        account = Account.find_by(slug: slug)
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')
        self.access_token = {
          :token =>  request.params['token'],
          :token_expires => 60
        }
        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.app_event_id'] = @app_event.id
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
        request_log = "AACD Authentication Request:\nGET #{user_info_url}, params: { token: #{access_token[:token]} }"
        @app_event.logs.create(level: 'info', text: request_log)

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

        response_log = "AACD Authentication Response (code: #{response&.code}): \n#{parsed_response}"

        if parsed_response['message'] == 'Success'
          @app_event.logs.create(level: 'info', text: response_log)
          info = {
            id: parsed_response['data']['IMIS'],
            first_name: parsed_response['data']['FirstName'],
            last_name: parsed_response['data']['LastName'],
            email: parsed_response['data']['Email'],
            member_level: parsed_response['data']['MemberLevel']
          }
          finalize_app_event(info)
          info
        else
          @app_event.logs.create(level: 'error', text: response_log)
          @app_event.fail!
          nil
        end
      end

      private

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

      def finalize_app_event(info)
        app_event_data = {
          user_info: {
            uid: info[:id],
            first_name: info[:first_name],
            last_name: info[:last_name],
            email: info[:email],
            member_level: info[:member_level]
          }
        }

        @app_event.update(raw_data: app_event_data)
      end
    end
  end
end

