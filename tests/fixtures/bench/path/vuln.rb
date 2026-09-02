class FilesController < ApplicationController
  def show
    name = params[:name]
    send_data File.read("/srv/files/#{name}")
  end
end
