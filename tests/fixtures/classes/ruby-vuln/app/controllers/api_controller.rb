class ApiController < ApplicationController
  before_action :require_key

  private

  def require_key
    head :unauthorized unless request.headers["X-Api-Key"] == ENV["API_KEY"]
  end
end
