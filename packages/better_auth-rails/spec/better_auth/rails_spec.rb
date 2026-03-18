# frozen_string_literal: true

require_relative "../spec_helper"

RSpec.describe BetterAuth::Rails do
  it "has a version number" do
    expect(BetterAuth::Rails::VERSION).not_to be nil
  end
end
