require "coffee-script"
require "digest/sha1"
require "haml"
require "fog"
require "pry" if ENV["RACK_ENV"] == "development"
require "sinatra"
require "tempfile"

configure do
  storage = Fog::Storage.new({
    :provider => 'AWS',
    :aws_access_key_id => ENV["ACCESS_KEY_ID"],
    :aws_secret_access_key => ENV["SECRET_ACCESS_KEY"],
  })

  set :bucket, ENV["AWS_BUCKET"]

  set :storage, storage
end

%w[
  editor
  game
  sifter
  slicer
  tiler
  uploader
].each do |component|
  get "/#{component}" do
    haml "%script(src='/#{component}.js')"
  end
end

get "/" do
  haml :editor
end

post "/upload" do
  if data = params[:data]
    if data.is_a? String
      content_type = params[:type]
      file = Tempfile.new ["data", ".json"]
      file.write data
      file.rewind
    else
      file = data[:tempfile]
      content_type = data[:type]
    end
  elsif data = params[:data_base64]
    content_type = params[:type]
    file = Tempfile.new ["image", ".png"], :encoding => 'ascii-8bit'
    file.write Base64.decode64(data)
    file.rewind
  else
    return 400
  end

  store(file, content_type)

  200
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

__END__
@@layout
!!!
%html
  %head
    %meta(charset="utf-8")

    %link(rel="stylesheet" type="text/css" href="/pixie.css")
    %link(rel="stylesheet" type="text/css" href="/main.css")

    %script(src="//ajax.googleapis.com/ajax/libs/jquery/1.10.1/jquery.min.js")
    %script(src="/coffee-script.js")
    %script(src="/jquery.gritter.min.js")
    %script(src="/sha1.js")
    %script(src="/enc-base64-min.js")
    %script(src="/pixie.js")
    %script(src="/underscore-min.js")
    %script(src="/main.js")
    %script(src="/templates.js")

  %body
    = yield

    %form#console
      %textarea
      %button Run

@@editor
%script(src="/editor.js")
