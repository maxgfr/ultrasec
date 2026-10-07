class TransfersController < ApplicationController
  protect_from_forgery with: :exception

  def create
    current_account.transfer!(params[:to], params[:amount])
  end
end
