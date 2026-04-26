# frozen_string_literal: true

module BetterAuth
  module Core
    def self.base_endpoints
      {
        ok: Routes.ok,
        error: Routes.error,
        sign_up_email: Routes.sign_up_email,
        sign_in_email: Routes.sign_in_email,
        sign_out: Routes.sign_out,
        get_session: Routes.get_session,
        list_sessions: Routes.list_sessions,
        revoke_session: Routes.revoke_session,
        revoke_sessions: Routes.revoke_sessions,
        revoke_other_sessions: Routes.revoke_other_sessions
      }
    end
  end
end
