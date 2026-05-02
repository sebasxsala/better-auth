# frozen_string_literal: true

require "stripe"

module BetterAuth
  module Stripe
    class ClientAdapter
      attr_reader :customers, :checkout, :billing_portal, :subscriptions, :prices, :subscription_schedules, :webhooks

      def initialize(api_key)
        client = ::Stripe::StripeClient.new(api_key)
        @customers = ResourceAdapter.new(client.v1.customers)
        @checkout = NamespaceAdapter.new(sessions: ResourceAdapter.new(client.v1.checkout.sessions))
        @billing_portal = NamespaceAdapter.new(sessions: ResourceAdapter.new(client.v1.billing_portal.sessions))
        @subscriptions = ResourceAdapter.new(client.v1.subscriptions)
        @prices = ResourceAdapter.new(client.v1.prices)
        @subscription_schedules = ResourceAdapter.new(client.v1.subscription_schedules)
        @webhooks = WebhooksAdapter.new
      end
    end

    class NamespaceAdapter
      def initialize(resources)
        resources.each do |name, resource|
          instance_variable_set(:"@#{name}", resource)
          self.class.attr_reader(name) unless respond_to?(name)
        end
      end
    end

    class ResourceAdapter
      def initialize(resource)
        @resource = resource
      end

      def create(params = {}, options = nil)
        options ? @resource.create(params || {}, options) : @resource.create(params || {})
      end

      def list(params = {})
        @resource.list(params || {})
      end

      def search(params = {})
        @resource.search(params || {})
      end

      def retrieve(id)
        @resource.retrieve(id)
      end

      def update(id, params = {})
        @resource.update(id, params || {})
      end

      def release(id)
        @resource.release(id)
      end
    end

    class WebhooksAdapter
      def construct_event(payload, signature, secret)
        ::Stripe::Webhook.construct_event(payload, signature, secret)
      end

      def construct_event_async(payload, signature, secret)
        construct_event(payload, signature, secret)
      end
    end
  end
end
