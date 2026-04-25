# frozen_string_literal: true

module BetterAuth
  module Adapters
    class Base
      attr_reader :options

      def initialize(options)
        @options = options
      end

      def create(**)
        raise NotImplementedError
      end

      def find_one(**)
        raise NotImplementedError
      end

      def find_many(**)
        raise NotImplementedError
      end

      def update(**)
        raise NotImplementedError
      end

      def update_many(**)
        raise NotImplementedError
      end

      def delete(**)
        raise NotImplementedError
      end

      def delete_many(**)
        raise NotImplementedError
      end

      def count(**)
        raise NotImplementedError
      end

      def transaction
        yield self
      end
    end
  end
end
