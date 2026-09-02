class RulesController < ApplicationController
  RULES = { "sum" => :sum_rule, "avg" => :avg_rule }.freeze

  def run
    name = params[:name]
    # A dispatch table keyed by an allow-listed name: nothing is evaluated.
    rule = RULES[name] || :sum_rule
    render plain: rule.to_s
  end
end
