# frozen_string_literal: true

module BetterAuth
  class DatabaseHooks
    attr_reader :adapter, :options

    def initialize(adapter, options)
      @adapter = adapter
      @options = options
    end

    def create(data, model, custom: nil, context: nil)
      run_before(model, :create, data, context) do |actual_data|
        created = custom ? custom.call(actual_data) : adapter.create(model: model, data: actual_data, force_allow_id: true)
        run_after(model, :create, created)
        created
      end
    end

    def update(data, where, model, custom: nil, context: nil)
      run_before(model, :update, data, context) do |actual_data|
        updated = custom ? custom.call(actual_data) : adapter.update(model: model, where: where, update: actual_data)
        run_after(model, :update, updated) if updated
        updated
      end
    end

    def update_many(data, where, model, custom: nil, context: nil)
      run_before(model, :update, data, context) do |actual_data|
        updated = custom ? custom.call(actual_data) : adapter.update_many(model: model, where: where, update: actual_data)
        run_after(model, :update, updated) if updated
        updated
      end
    end

    def delete(where, model, custom: nil, context: nil)
      entity = adapter.find_one(model: model, where: where)
      return custom ? custom.call(where) : adapter.delete(model: model, where: where) unless entity

      return nil if before_hooks(model, :delete).any? { |hook| hook.call(entity, context) == false }

      deleted = custom ? custom.call(where) : adapter.delete(model: model, where: where)
      after_hooks(model, :delete).each { |hook| hook.call(entity, context) }
      deleted
    end

    def delete_many(where, model, custom: nil, context: nil)
      entities = adapter.find_many(model: model, where: where)
      entities.each do |entity|
        return nil if before_hooks(model, :delete).any? { |hook| hook.call(entity, context) == false }
      end
      deleted = custom ? custom.call(where) : adapter.delete_many(model: model, where: where)
      entities.each { |entity| after_hooks(model, :delete).each { |hook| hook.call(entity, context) } }
      deleted
    end

    private

    def run_before(model, action, data, context)
      actual_data = stringify_keys(data)
      before_hooks(model, action).each do |hook|
        result = hook.call(actual_data, context)
        return nil if result == false

        hook_data = result.is_a?(Hash) ? (result[:data] || result["data"]) : nil
        actual_data = actual_data.merge(stringify_keys(hook_data)) if hook_data
      end
      yield actual_data
    end

    def run_after(model, action, data)
      after_hooks(model, action).each { |hook| hook.call(data, nil) }
    end

    def before_hooks(model, action)
      hooks_for(model, action, :before)
    end

    def after_hooks(model, action)
      hooks_for(model, action, :after)
    end

    def hooks_for(model, action, phase)
      all_hooks.filter_map do |hooks|
        model_hooks = hooks[model.to_sym] || hooks[model.to_s]
        action_hooks = model_hooks&.fetch(action, nil) || model_hooks&.fetch(action.to_s, nil)
        action_hooks&.fetch(phase, nil) || action_hooks&.fetch(phase.to_s, nil)
      end
    end

    def all_hooks
      direct = if options.database_hooks.nil?
        []
      elsif options.database_hooks.is_a?(Array)
        options.database_hooks
      else
        [options.database_hooks]
      end
      plugin_hooks = options.plugins.filter_map do |plugin|
        init_options = plugin.dig(:options, :database_hooks) || plugin.dig("options", "databaseHooks")
        plugin[:database_hooks] || plugin["databaseHooks"] || init_options
      end
      direct + plugin_hooks
    end

    def stringify_keys(data)
      return {} unless data

      data.each_with_object({}) do |(key, value), result|
        result[Schema.storage_key(key)] = value
      end
    end
  end
end
