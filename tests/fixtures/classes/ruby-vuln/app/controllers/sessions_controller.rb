class SessionsController < ApplicationController
  def create
    cookies[:sid] = session_token
    redirect_to root_path
  end
end
