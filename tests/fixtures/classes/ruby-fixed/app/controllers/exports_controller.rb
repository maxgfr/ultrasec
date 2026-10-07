class ExportsController < ApplicationController
  def index
    users = User.order(:id).limit(500).offset(params[:offset].to_i)
    render json: users
  end
end
