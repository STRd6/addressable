task :empty_bucket do
  require 'fog'
  require 'pry'

  storage = Fog::Storage.new({
    :provider => 'AWS',
    :aws_access_key_id => ENV["ACCESS_KEY_ID"],
    :aws_secret_access_key => ENV["SECRET_ACCESS_KEY"],
  })

  bucket = ENV["AWS_BUCKET"]

  directory = storage.directories.get(bucket)

  files = directory.files.map(&:key)

  storage.delete_multiple_objects(bucket, files)
end
