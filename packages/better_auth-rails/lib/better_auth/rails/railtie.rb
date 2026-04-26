# frozen_string_literal: true

module BetterAuth
  module Rails
    class Railtie < ::Rails::Railtie
      initializer "better_auth_rails.routes" do
        ActiveSupport.on_load(:action_dispatch_routing) do
          include BetterAuth::Rails::Routing
        end
      end

      rake_tasks do
        load File.expand_path("../../tasks/better_auth.rake", __dir__)
      end
    end
  end
end
