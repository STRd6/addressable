task :default => [:build]

task :build do
  src_files = Dir["source/*.coffee"]
  sh "coffee", "-bcj", "public/main.js", *src_files

  %w[
    editor
    game
    slicer
    sifter
    tiler
    uploader
  ].each do |subdir|
    src_files = Dir["source/#{subdir}/*.coffee"]
    sh "coffee", "-bcj", "public/#{subdir}.js", *src_files
  end

  sh "cat source/*.styl | stylus > public/main.css"

  sh "haml-coffee -i source/templates/ -o public/templates.js -b true"
end
