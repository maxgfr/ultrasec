class UsersController < ApplicationController
  def index
    q = params[:q]
    @users = User.where("name = '#{q}'")
  end
end
