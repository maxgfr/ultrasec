Rails.application.configure do
  config.consider_all_requests_local = false
  config.action_dispatch.ip_spoofing_check = true
end
