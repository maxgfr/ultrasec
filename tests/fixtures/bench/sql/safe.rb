class UsersController < ApplicationController
  def show
    q = params[:q]
    # Primary-key lookup on a coerced integer: no fragment is built from input.
    @user = User.find(q.to_i)
  end
end
