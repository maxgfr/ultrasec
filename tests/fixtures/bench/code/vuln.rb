class RulesController < ApplicationController
  def run
    code = params[:code]
    result = Object.new.instance_eval(code)
    render plain: result.to_s
  end
end
