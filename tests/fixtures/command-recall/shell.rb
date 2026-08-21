def handler(params)
  cmd = params[:c]
  system(cmd)
  Open3.capture3(cmd)
end
