require "csv"

module UsersCsv
  def self.build(users)
    CSV.generate do |csv|
      users.each { |u| csv << [u.name, u.email] }
    end
  end
end
