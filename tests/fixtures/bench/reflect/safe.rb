class ReportsController < ApplicationController
  def show
    field = params[:field]
    report = Report.first
    # An explicit case on the allowed names; no method is resolved by string.
    value =
      case field
      when "title" then report.title
      when "owner" then report.owner
      else ""
      end
    render plain: value
  end
end
