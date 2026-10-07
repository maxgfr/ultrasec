class TransfersController < ApplicationController
  skip_before_action :verify_authenticity_token

  def create
    current_account.transfer!(params[:to], params[:amount])
  end
end
