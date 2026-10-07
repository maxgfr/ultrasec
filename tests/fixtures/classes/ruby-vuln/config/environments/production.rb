Rails.application.configure do
  config.consider_all_requests_local = true
  config.action_dispatch.ip_spoofing_check = false
end
