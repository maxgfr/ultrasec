module Flags
  FAKE_CLOCK = ActiveModel::Type::Boolean.new.cast(ENV["FAKE_CLOCK"])
end
