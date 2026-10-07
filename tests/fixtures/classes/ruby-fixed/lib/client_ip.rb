module ClientIp
  # ActionDispatch::RemoteIp walks X-Forwarded-For from the right, skipping trusted proxies.
  def self.of(request)
    request.remote_ip
  end
end
