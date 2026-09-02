require 'uri'

class ProxyController < ApplicationController
  ALLOWED = %w[api.example.com cdn.example.com].freeze

  def fetch
    url = params[:url]
    # Only the host is inspected; nothing is requested from the input here.
    host = URI.parse(url).host
    head(ALLOWED.include?(host) ? :ok : :bad_request)
  end
end
