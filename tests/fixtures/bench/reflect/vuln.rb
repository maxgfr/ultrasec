class ReportsController < ApplicationController
  def show
    field = params[:field]
    report = Report.first
    render plain: report.public_send(field).to_s
  end
end
