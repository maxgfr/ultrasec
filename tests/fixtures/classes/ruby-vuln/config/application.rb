require_relative "boot"
require "rails/all"

module Demo
  class Application < Rails::Application
    config.load_defaults 7.1
    config.action_dispatch.default_headers = {}
  end
end
