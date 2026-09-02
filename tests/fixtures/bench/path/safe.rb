class FilesController < ApplicationController
  ALLOWED = %w[report.pdf terms.pdf].freeze

  def show
    name = File.basename(params[:name])
    # Allow-listed name; nothing is read from the input.
    head(ALLOWED.include?(name) ? :ok : :not_found)
  end
end
