module ClientIp
  def self.of(request)
    request.env["HTTP_X_FORWARDED_FOR"].to_s.split(",").first
  end
end
