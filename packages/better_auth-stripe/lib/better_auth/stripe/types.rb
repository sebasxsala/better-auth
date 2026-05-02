# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Types
      CUSTOMER_TYPES = %w[user organization].freeze
      AUTHORIZE_REFERENCE_ACTIONS = %w[
        upgrade-subscription
        cancel-subscription
        restore-subscription
        billing-portal
        list-subscriptions
      ].freeze

      module_function
    end
  end
end
