class ApiController < ApplicationController
  before_action :require_key

  private

  def require_key
    provided = request.headers["X-Api-Key"].to_s
    head :unauthorized unless ActiveSupport::SecurityUtils.secure_compare(provided, ENV.fetch("API_KEY"))
  end
end
