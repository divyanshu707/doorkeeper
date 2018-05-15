module Doorkeeper
  module OAuth
    class RefreshTokenRequest
      include Validations
      include OAuth::RequestConcern
      include OAuth::Helpers

      validate :token_presence, error: :invalid_request
      validate :token,        error: :invalid_grant
      validate :client,       error: :invalid_client
      validate :client_match, error: :invalid_grant
      validate :scope,        error: :invalid_scope

      attr_accessor :access_token, :client, :credentials, :refresh_token,
                    :server, :refresh_token_parameter

      private :refresh_token_parameter, :refresh_token_parameter=

      def initialize(server, refresh_token, credentials, parameters = {})
        @server          = server
        @refresh_token   = refresh_token
        @credentials     = credentials
        @original_scopes = parameters[:scope] || parameters[:scopes]
        @refresh_token_parameter = parameters[:refresh_token]

        if credentials
          @client = Application.by_uid_and_secret credentials.uid,
                                                  credentials.secret
        end
      end

      private

      def before_successful_response
        refresh_token.transaction do
          refresh_token.lock!
          raise Errors::InvalidTokenReuse if refresh_token.revoked?

          refresh_token.revoke unless refresh_token_revoked_on_use?
          create_access_token
        end
      end

      def refresh_token_revoked_on_use?
        Doorkeeper::AccessToken.refresh_token_revoked_on_use?
      end

      def default_scopes
        refresh_token.scopes
      end

      def create_access_token
        @access_token = AccessToken.new(access_token_attributes)
        @access_token.save!
        @access_token.refresh_token ||= get_latest_of_prev_access_tokens.refresh_token
      end

      def access_token_attributes
        {
          application_id: refresh_token.application_id,
          resource_owner_id: refresh_token.resource_owner_id,
          scopes: scopes.to_s,
          expires_in: access_token_expires_in,
          use_refresh_token: use_refresh_token?
        }.tap do |attributes|
          if refresh_token_revoked_on_use?
            attributes[:previous_refresh_token] = refresh_token.refresh_token
          end
        end
      end

      def use_refresh_token?
        @prev_access_tokens ||= AccessToken.where(previous_refresh_token: refresh_token.refresh_token)
        @prev_access_tokens.count == 0
      end

      def get_latest_of_prev_access_tokens
        @prev_access_tokens.find{|token| token.refresh_token.present?}
      end

      def access_token_expires_in
        Authorization::Token.access_token_expires_in(server, client)
      end

      def validate_token_presence
        refresh_token.present? || refresh_token_parameter.present?
      end

      def validate_token
        refresh_token.present? && !refresh_token.revoked?
      end

      def validate_client
        !credentials || !!client
      end

      def validate_client_match
        !client || refresh_token.application_id == client.id
      end

      def validate_scope
        if @original_scopes.present?
          ScopeChecker.valid?(@original_scopes, refresh_token.scopes)
        else
          true
        end
      end
    end
  end
end
