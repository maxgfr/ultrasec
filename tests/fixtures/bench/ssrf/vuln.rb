require 'net/http'

class ProxyController < ApplicationController
  def fetch
    url = params[:url]
    body = Net::HTTP.get(URI(url))
    render plain: body
  end
end
