require "base64"
require "digest/sha1"
require "fog"
require "json"
require "openssl"
require "pry" if ENV["RACK_ENV"] == "development"
require "sinatra"
require "unf"

require "rack/cors"

use Rack::Cors do |config|
  config.allow do |allow|
    allow.origins '*'
    allow.resource '*', :headers => :any
  end
end

configure do
  set :aws_access_key_id, ENV["ACCESS_KEY_ID"]
  set :aws_secret_key, ENV["SECRET_ACCESS_KEY"]

  set :bucket, ENV["AWS_BUCKET"]

  storage = Fog::Storage.new({
    :provider => 'AWS',
    :aws_access_key_id => settings.aws_access_key_id,
    :aws_secret_access_key => settings.aws_secret_key,
  })

  set :storage, storage
end

post "/" do
  if data = params[:data]
    file = data[:tempfile]
    content_type = data[:type]
  else
    return 400
  end

  store(file, content_type)

  200
end

get "/policy.json" do
  max_size = 10 * 1024 * 1024
  policy_document = {
    expiration: "2020-12-01T12:00:00.000Z",
    conditions: [
      { bucket: settings.bucket},
      ["starts-with", "$key", ""],
      { acl: "public"},
      ["starts-with", "$Content-Type", ""],
      ["content-length-range", 0, max_size]
    ]
  }.to_json

  encoded_policy_document = Base64.encode64(policy_document).gsub("\n","")

  content_type :json

  {
    :policy => encoded_policy_document,
    :signature => sign_policy(encoded_policy_document)
  }.to_json
end

def directory
  settings.storage.directories.get(settings.bucket)
end

def store(file, content_type=nil)
  sha1 = Digest::SHA1.file(file.path).hexdigest

  if directory.files.get(sha1)
    # Already stored, do nothing
  else
    directory.files.create(
      :key => sha1,
      :body => file,
      :content_type => content_type,
      :public => true,
      :metadata => {
        'Cache-Control' => 'max-age=315576000'
      }
    )
  end
end

def sign_policy(base64_encoded_policy_document)
  signature = Base64.encode64(
    OpenSSL::HMAC.digest(
      OpenSSL::Digest::Digest.new('sha1'),
      settings.aws_secret_key,
      base64_encoded_policy_document
    )
  ).gsub("\n","")
end
