# == CeWL Library: Library to outsource reusable features
#
# Author:: Robin Wood (robin@digi.ninja)
# Copyright:: Copyright (c) Robin Wood 2016
# Licence:: GPL
#

begin
	require 'mini_exiftool'
	require "zip"
	require "rexml/document"
	require 'mime'
	require 'mime-types'
	include REXML
rescue LoadError => e
	# catch error and prodive feedback on installing gem
	if e.to_s =~ /cannot load such file -- (.*)/
		missing_gem = $1
		puts "\nError: #{missing_gem} gem not installed\n"
		puts "\t use: \"gem install #{missing_gem}\" to install the required gem\n\n"
		exit
	else
		puts "There was an error loading the gems:"
		puts
		puts e.to_s
		exit
	end
end

# Override the MiniExiftool class so that I can modify the parse_line
# method and force all encoding to ISO-8859-1. Without this the app bombs
# on some machines as it is unable to parse UTF-8
class MyMiniExiftool<MiniExiftool
	def parse_line line
		line.force_encoding('ISO-8859-1')
		super	
	end
end

# == Synopsis
#
# This library contains functions to evaulate files found while running CeWL
#
# Author:: Robin Wood (robin@digi.ninja)
# Copyright:: Copyright (c) Robin Wood 2021
# Licence:: GPL
#

# Get data from a pdf file using regexps
def get_pdf_data(pdf_file, verbose)
	meta_data=[]
	begin
		interesting_fields=Array.[]("/Author")

		f=File.open(pdf_file)
		f.each_line{ |line|
			line.force_encoding('ISO-8859-1')
			if /pdf:Author='([^']*)'/.match(line)
				if verbose
					puts "Found pdf:Author: "+$1
				end
				meta_data<<$1.to_s.chomp unless $1.to_s==""
			end
			if /xap:Author='([^']*)'/i.match(line)
				if verbose
					puts "Found xap:Author: "+$1
				end
				meta_data<<$1.to_s.chomp unless $1.to_s==""
			end
			if /dc:creator='([^']*)'/i.match(line)
				if verbose
					puts "Found dc:creator: "+$1
				end
				meta_data<<$1.to_s.chomp unless $1.to_s==""
			end
			if /\/Author ?\(([^\)]*)\)/i.match(line)
				if verbose
					puts "Found Author: "+$1
				end
				meta_data<<$1.to_s.chomp unless $1.to_s==""
			end
			if /<xap:creator>(.*)<\/xap:creator>/i.match(line)
				if verbose
					puts "Found pdf:creator: "+$1
				end
				meta_data<<$1.to_s.chomp unless $1.to_s==""
			end
			if /<xap:Author>(.*)<\/xap:Author>/i.match(line)
				if verbose
					puts "Found xap:Author: "+$1
				end
				meta_data<<$1.to_s.chomp unless $1.to_s==""
			end
			if /<pdf:Author>(.*)<\/pdf:Author>/i.match(line)
				if verbose
					puts "Found pdf:Author: "+$1
				end
				meta_data<<$1.to_s.chomp unless $1.to_s==""
			end
			if /<dc:creator>(.*)<\/dc:creator>/i.match(line)
				if verbose
					puts "Found dc:creator: "+$1
				end
				meta_data<<$1.to_s.chomp unless $1.to_s==""
			end
			
		}
		return meta_data
	rescue => e
		if verbose
			puts "There was an error processing the document - " + e.message
		end
	end
	return meta_data
end

# Get data from files using exiftool
def get_doc_data(doc_file, verbose)
	data=[]
	begin
		interesting_fields=Array.[]("Author","LastSavedBy","Creator")
		file = MyMiniExiftool.new(doc_file)

		interesting_fields.each{ |field_name|
			if file.tags.include?(field_name)
				data<<file[field_name].to_s
			end
		}
	rescue => e
		if verbose
			puts "There was an error processing the document - " + e.message
		end
	end
	return data
end

# Get data from Office 2007 documents by unziping relivant XML files then
# checking for known fields
def get_docx_data(docx_file, verbose)
	meta_data=[]

	interesting_fields=Array.[]("cp:coreProperties/dc:creator","cp:coreProperties/cp:lastModifiedBy")
	interesting_files=Array.[]("docProps/core.xml")

	begin
		Zip::File.open(docx_file) { |zipfile|
			interesting_files.each { |file|
				if zipfile.find_entry(file)
					xml=zipfile.read(file)

					doc=Document.new(xml)
					interesting_fields.each { |field|
						element=doc.elements[field]
						#puts element.get_text unless element==nil||element.get_text==nil
						meta_data<<element.get_text.to_s.chomp unless element==nil||element.get_text==nil
					}
				end
			}
		}
	rescue => e
		if verbose
			# not a zip file
			puts "File probably not a zip file - " + e.message
		end
	end
	return meta_data
end

# Take the file given, try to work out what type of file it is then pass it
# to the relivant function to try to grab meta data
def process_file(filename, verbose=false)
	meta_data=nil

	begin
		puts "processing file: " + filename

		if File.file?(filename) && File.exist?(filename)
			mime_types=MIME::Types.type_for(filename)
			if(mime_types.size==0)
				if(verbose)
					puts "Empty mime type"
				end
				return meta_data
			end
			if verbose
				puts "Checking "+filename
				puts "  Mime type="+mime_types.join(", ")
				puts
			end
			if mime_types.include?("application/word") || mime_types.include?("application/excel") || mime_types.include?("application/powerpoint")
				if verbose
					puts "  Mime type says original office document"
				end
				meta_data=get_doc_data(filename, verbose)
			else
				if mime_types.include?("application/pdf")
					if verbose
						puts "  Mime type says PDF"
					end
					# Running both my own regexp and exiftool on pdfs as I've found exif misses some data
					meta_data=get_doc_data(filename, verbose)
					meta_data+=get_pdf_data(filename, verbose)
				else
					# list taken from http://en.wikipedia.org/wiki/Microsoft_Office_2007_file_extensions
					if filename =~ /(.(doc|dot|ppt|pot|xls|xlt|pps)[xm]$)|(.ppam$)|(.xlsb$)|(.xlam$)/
						if verbose
							puts "  File extension says 2007 style office document"
						end
						meta_data=get_docx_data(filename, verbose)
					elsif filename =~ /.php$|.aspx$|.cfm$|.asp$|.html$|.htm$/
						if verbose
							puts "  Language file, can ignore"
						end
					else
						if verbose
							puts "  Unknown file type"
						end
					end
				end
			end
			if meta_data!=nil
				if verbose
					if meta_data.length > 0
						puts "  Found "+meta_data.join(", ")+"\n"
					end
				end
			end
		end
	rescue => e
		puts "Problem in process_file function"
		puts "Error: " + e.message
		puts e.backtrace
	end

	return meta_data
end
#
# A simple way to check if a string is a valid integer
# 
# Usage:
#
# str = "123"
# if str.valid_int? then
#   int = str.to_i
# end
#
class String
	def valid_int?
		true if Integer self rescue false
	end
end

# Doing this so I can override the allowed? function which normally checks
# the robots.txt file
class MySpider<Spider
	@@proxy_host = nil
	@@proxy_port = nil
	@@proxy_username = nil
	@@proxy_password = nil

	@@headers = nil

	@@auth_type = nil
	@@auth_user = nil
	@@auth_password = nil
	@@verbose = false
	@@debug = false

	def self.proxy (host, port = nil, username = nil, password = nil)
		@@proxy_host = host
		port = 8080 if port.nil?
		@@proxy_port = port
		@@proxy_username = username
		@@proxy_password = password
	end

	def self.headers (headers)
		header_hash = {}
		headers.each do |header|
			header_split = header.split(":")
			if (header_split.count == 2)
				header_hash[header_split[0].strip] = header_split[1].strip
			else
				puts "Invalid header: " + header.inspect
			end
		end
		@@headers = header_hash
	end

	def self.auth_creds (type, user, password)
		@@auth_type = type
		@@auth_user = user
		@@auth_password = password
	end

	def self.verbose (val)
		@@verbose = val
	end

	def self.debug (val)
		@@debug = val
	end

	# Create an instance of MySpiderInstance rather than SpiderInstance
	def self.start_at(a_url, &block)
		rules = RobotRules.new('Ruby Spider 1.0')
		a_spider = MySpiderInstance.new({nil => a_url}, [], rules, [])

		a_spider.headers = @@headers

		a_spider.auth_type = @@auth_type
		a_spider.auth_user = @@auth_user
		a_spider.auth_password = @@auth_password

		a_spider.proxy_host = @@proxy_host
		a_spider.proxy_port = @@proxy_port
		a_spider.proxy_username = @@proxy_username
		a_spider.proxy_password = @@proxy_password

		a_spider.verbose = @@verbose
		a_spider.debug = @@debug
		block.call(a_spider)
		a_spider.start!
	end
end

# My version of the spider class which allows all files
# to be processed
class MySpiderInstance<SpiderInstance
	attr_writer :auth_type
	attr_writer :auth_user
	attr_writer :auth_password

	attr_writer :headers

	attr_writer :proxy_host
	attr_writer :proxy_port
	attr_writer :proxy_username
	attr_writer :proxy_password

	attr_writer :verbose
	attr_writer :debug

	attr_writer :interrupt

	# Force all files to be allowed
	# Normally the robots.txt file will be honoured
	def allowed?(a_url, parsed_url)
		true
	end

	# Lifted from the original gem to fix the case statement
	# which checked for Fixednum not Integer as
	# Fixednum has been deprecated.
	#
	def on(code, p = nil, &block)
		f = p ? p : block
		case code
		when Integer
			@callbacks[code] = f
		else
			@callbacks[code.to_sym] = f
		end
	end

	def start! #:nodoc:
		trap("SIGINT") { puts 'Hold on, about to stop ...'; @interrupt = true }
		begin
			next_urls = @next_urls.pop
			#tmp_n_u = {}
			next_urls.each do |prior_url, urls|
				x = []

				urls.each_line do |a_url|
					x << [a_url, (URI.parse(a_url) rescue nil)]
				end

				y = []
				x.select do |a_url, parsed_url|
					y << [a_url, parsed_url] if allowable_url?(a_url, parsed_url)
				end

				y.each do |a_url, parsed_url|
					@setup.call(a_url) unless @setup.nil?
					get_page(parsed_url) do |response|
						do_callbacks(a_url, response, prior_url)
						#tmp_n_u[a_url] = generate_next_urls(a_url, response)
						#@next_urls.push tmp_n_u
						generate_next_urls(a_url, response).each do |a_next_url|
							puts "Pushing #{a_next_url}" if @debug
							@next_urls.push a_url => a_next_url
						end
						#exit if interrupted
					end

					@teardown.call(a_url) unless @teardown.nil?
					throw :ctrl_c if @interrupt
				end
			end
		end while !@next_urls.empty?
	end

	def get_page(uri, &block) #:nodoc:
		@seen << uri

		trap("SIGINT") { puts 'Hold on, stopping here ...'; @interrupt = true }
		begin
			if @proxy_host.nil?
				http = Net::HTTP.new(uri.host, uri.port)

				if uri.scheme == 'https'
					http.use_ssl = true
					http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				end
			else
				proxy = Net::HTTP::Proxy(@proxy_host, @proxy_port, @proxy_username, @proxy_password)
				begin
					if uri.scheme == 'https'
						http = proxy.start(uri.host, uri.port, :use_ssl => true, :verify_mode => OpenSSL::SSL::VERIFY_NONE)
					else
						http = proxy.start(uri.host, uri.port)
					end
				rescue => e
					puts "\nFailed to connect to the proxy (#{@proxy_host}:#{@proxy_port})\n\n"
					exit 2
				end
			end

			req = Net::HTTP::Get.new(uri.request_uri)
			@headers.each_pair do |header, value|
				req[header] = value
			end

			if @auth_type
				case @auth_type
					when "digest"
						uri.user = @auth_user
						uri.password = @auth_password

						res = http.request req

						if res['www-authenticate']
							digest_auth = Net::HTTP::DigestAuth.new
							auth = digest_auth.auth_header uri, res['www-authenticate'], 'GET'

							req = Net::HTTP::Get.new uri.request_uri
							req.add_field 'Authorization', auth
						end

					when "basic"
						req.basic_auth @auth_user, @auth_password
				end
			end

			res = http.request(req)

			if res.redirect?
				puts "Redirect URL" if @debug
				base_url = uri.to_s[0, uri.to_s.rindex('/')]
				new_url = URI.parse(construct_complete_url(base_url, res['Location']))

				# If auth is used then a name:pass@ gets added, this messes the tree
				# up so easiest to just remove it
				current_uri = uri.to_s.gsub(/:\/\/[^:]*:[^@]*@/, "://")
				@next_urls.push current_uri => new_url.to_s
			elsif res.code == "401"
				puts "Authentication required, can't continue on this branch - #{uri}" if @verbose
			else
				block.call(res)
			end
		rescue Zlib::DataError => e
			puts "Error in Zlib decompressing data on #{uri}, moving on regardless"
		rescue SocketError, Errno::EHOSTUNREACH => e
			puts "Couldn't hit the site #{uri}, moving on"
		rescue NoMethodError => e
			if @verbose
				puts "Unable to process URL"
				puts "Message is #{e.to_s}"
				puts e.backtrace
			end
		rescue => e
			puts "\nUnable to connect to the site (#{uri.scheme}://#{uri.host}:#{uri.port}#{uri.request_uri})"

			if @verbose
				puts "\nThe following error may help:"
				puts e.to_s
				puts e.backtrace
				puts "\nCaller"
				puts caller
			else
				puts "Run in verbose mode (-v) for more information"
			end

			puts "\n\n"
		end
	end

	# Overriding so that I can get it to ignore direct names - i.e. #name
	def construct_complete_url(base_url, additional_url, parsed_additional_url = nil) #:nodoc:
		return nil if additional_url =~ /^#/

		parsed_additional_url ||= URI.parse(additional_url)
		if parsed_additional_url.scheme.nil?
			u = base_url.is_a?(URI) ? base_url : URI.parse(base_url)
			if additional_url[0].chr == '/'
				url = "#{u.scheme}://#{u.host}:#{u.port}#{additional_url}"
			elsif u.path.nil? || u.path == ''
				url = "#{u.scheme}://#{u.host}:#{u.port}/#{additional_url}"
			elsif u.path[0].chr == '/'
				url = "#{u.scheme}://#{u.host}:#{u.port}#{u.path}/#{additional_url}"
			else
				url = "#{u.scheme}://#{u.host}:#{u.port}/#{u.path}/#{additional_url}"
			end
		else
			url = additional_url
		end
		return url
	end

	# Overriding the original spider one as it doesn't find hrefs very well
	def generate_next_urls(a_url, resp) #:nodoc:
		if @debug
			puts "a_url = #{a_url}"
			puts "resp = #{resp}"
		end
		web_page = resp.body
		if URI.parse(a_url).path.empty?
			base_url = a_url
		else
			base_url = a_url[0, a_url.rindex('/')]
		end
		puts "base_url: #{base_url}" if @debug

		doc = Nokogiri::HTML(web_page)
		links = doc.css('a').map { |a| a['href'] }

		puts "links = #{links.inspect}" if @debug
		links.map do |link|
			begin
				if link.nil?
					nil
				else
					begin
						parsed_link = URI.parse(link)
						parsed_link.fragment == '#' ? nil : construct_complete_url(base_url, link, parsed_link)
					rescue
						nil
					end
				end
			rescue => e
				puts "\nThere was an error generating URL list"
				puts "Error: #{e.inspect}"
				puts e.backtrace
				exit 2
			end
		end.compact
	end
end

# A node for a tree
class TreeNode
	attr :value
	attr :depth
	attr :key
	attr :visited, true

	def initialize(key, value, depth)
		@key = key
		@value = value
		@depth = depth
		@visited = false
	end

	def to_s
		if key.nil?
			return "key=nil value=#{@value} depth=#{@depth.to_s} visited=#{@visited.to_s}"
		else
			return "key=#{@key} value=#{@value} depth=#{@depth.to_s} visited=#{@visited.to_s}"
		end
	end

	def to_url_hash
		return({@key => @value})
	end
end

# A tree structure
class Tree
	attr :data
	attr_writer :debug
	attr_writer :max_depth
	@children

	# Get the maximum depth the tree can grow to
	def max_depth
		@max_depth
	end

	# Set the max depth the tree can grow to
	def max_depth=(val)
		@max_depth = Integer(val)
	end

	# As this is used to work out if there are any more nodes to process it isn't a true empty
	def empty?
		if !@data.visited
			return false
		else
			@children.each { |node|
				return false if !node.data.visited
			}
		end
		return true
	end

	# The constructor
	def initialize(key=nil, value=nil, depth=0, debug=false)
		@data = TreeNode.new(key, value, depth)
		@children = []
		@max_depth = 2
	end

	# Itterator
	def each
		yield @data
		@children.each do |child_node|
			child_node.each { |e| yield e }
		end
	end

	# Remove an item from the tree
	def pop
		if !@data.visited
			@data.visited = true
			return @data.to_url_hash
		else
			@children.each { |node|
				if !node.data.visited
					node.data.visited = true
					return node.data.to_url_hash
				end
			}
		end
		return nil
	end

	# Push an item onto the tree
	def push(value)
		puts "Pushing #{value}" if @debug
		key = value.keys.first
		value = value.values_at(key).first

		if key.nil?
			@data = TreeNode.new(key, value, 0)
		else
			# If the depth is 0 then don't add anything to the tree
			return if @max_depth == 0
			if key == @data.value
				child = Tree.new(key, value, @data.depth + 1, @debug)
				@children << child
			else
				@children.each { |node|
					if node.data.value == key && node.data.depth<@max_depth
						child = Tree.new(key, value, node.data.depth + 1, @debug)
						@children << child
					end
				}
			end
		end
	end
end

