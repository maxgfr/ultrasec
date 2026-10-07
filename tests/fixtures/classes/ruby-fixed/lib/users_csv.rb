require "csv"

module UsersCsv
  def self.cell(value)
    s = value.to_s
    s.start_with?("=", "+", "-", "@", "\t", "\r") ? "'#{s}" : s
  end

  def self.build(users)
    CSV.generate do |csv|
      users.each { |u| csv << [cell(u.name), cell(u.email)] }
    end
  end
end
