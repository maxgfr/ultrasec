class SessionsController < ApplicationController
  def create
    cookies[:sid] = { value: session_token, httponly: true, secure: true, same_site: :lax }
    redirect_to root_path
  end
end
