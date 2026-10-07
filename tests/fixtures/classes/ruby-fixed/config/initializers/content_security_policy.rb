Rails.application.configure do
  config.content_security_policy do |policy|
    policy.default_src :self, :https
    policy.script_src  :self
  end
end
