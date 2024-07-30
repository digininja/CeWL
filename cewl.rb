#!/usr/bin/env ruby
#encoding: UTF-8

# == CeWL: Custom Word List Generator
#
# CeWL will spider a target site and generate the following lists:
#
# * A word list of all unique words found on the target site
# * A list of all email addresses found in mailto links
# * A list of usernames/author details from meta data found in any documents on the site
# * Groups of words up to the specified group size
#
# URL: The site to spider.
#
# Author:: Robin Wood (robin@digi.ninja)
# Copyright:: Copyright (c) Robin Wood 2018
# Licence:: CC-BY-SA 2.0 or GPL-3+
#

VERSION = "6.2.1 (More Fixes)"

puts "CeWL #{VERSION} Robin Wood (robin@digi.ninja) (https://digi.ninja/)\n"

begin
	require 'getoptlong'
	require 'spider'
	require 'nokogiri'
	require 'net/http'
rescue LoadError => e
	# Catch error and provide feedback on installing gem
	if e.to_s =~ /cannot load such file -- (.*)/
		missing_gem = $1
		puts "\nError: #{missing_gem} gem not installed\n"
		puts "    Run 'bundle install' to install all the required gems\n\n"
		exit 2
	else
		puts "There was an error loading the gems:\n"
		puts e.to_s
		exit 2
	end
end

require_relative 'cewl_lib'

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
                    if (not parsed_url.nil?) then
                      if (parsed_url.scheme == "mailto" or parsed_url.scheme == "http" or parsed_url.scheme == "https") then
                        y << [a_url, parsed_url] if allowable_url?(a_url, parsed_url)
                      end
                    end
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
		puts "Adding #{value} to the tree" if @debug
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
                    # Ignore the max depth for mailto links.
                    # This is not a good way to do this, but it will work for now
                    # and we all know dirty hacks stay around forever so don't
                    # expect this to be fixed for a while.
                    if value =~ /^mailto:/ then
                      if node.data.value == key then
                          child = Tree.new(key, value, node.data.depth + 1, @debug)
                          @children << child
                      end
                    else
                      if node.data.value == key && node.data.depth<@max_depth then
                          child = Tree.new(key, value, node.data.depth + 1, @debug)
                          @children << child
                      end
                    end
				}
			end
		end
	end
end

opts = GetoptLong.new(
		['--help', '-h', GetoptLong::NO_ARGUMENT],
		['--keep', '-k', GetoptLong::NO_ARGUMENT],
		['--depth', '-d', GetoptLong::REQUIRED_ARGUMENT],
		['--min_word_length', "-m", GetoptLong::REQUIRED_ARGUMENT],
		['--max_word_length', "-x", GetoptLong::REQUIRED_ARGUMENT],
		['--no-words', "-n", GetoptLong::NO_ARGUMENT],
		['--groups', "-g", GetoptLong::REQUIRED_ARGUMENT],
		['--offsite', "-o", GetoptLong::NO_ARGUMENT],
		['--exclude', GetoptLong::REQUIRED_ARGUMENT],
		['--allowed', GetoptLong::REQUIRED_ARGUMENT],
		['--write', "-w", GetoptLong::REQUIRED_ARGUMENT],
		['--ua', "-u", GetoptLong::REQUIRED_ARGUMENT],
		['--meta-temp-dir', GetoptLong::REQUIRED_ARGUMENT],
		['--meta_file', GetoptLong::REQUIRED_ARGUMENT],
		['--email_file', GetoptLong::REQUIRED_ARGUMENT],
		['--lowercase', GetoptLong::NO_ARGUMENT],
		['--with-numbers', GetoptLong::NO_ARGUMENT],
		['--convert-umlauts', GetoptLong::NO_ARGUMENT],
		['--meta', "-a", GetoptLong::NO_ARGUMENT],
		['--email', "-e", GetoptLong::NO_ARGUMENT],
		['--count', '-c', GetoptLong::NO_ARGUMENT],
		['--auth_user', GetoptLong::REQUIRED_ARGUMENT],
		['--auth_pass', GetoptLong::REQUIRED_ARGUMENT],
		['--auth_type', GetoptLong::REQUIRED_ARGUMENT],
		['--header', "-H", GetoptLong::REQUIRED_ARGUMENT],
		['--proxy_host', GetoptLong::REQUIRED_ARGUMENT],
		['--proxy_port', GetoptLong::REQUIRED_ARGUMENT],
		['--proxy_username', GetoptLong::REQUIRED_ARGUMENT],
		['--proxy_password', GetoptLong::REQUIRED_ARGUMENT],
		["--verbose", "-v", GetoptLong::NO_ARGUMENT],
		["--debug", GetoptLong::NO_ARGUMENT]
)

# Display the usage
def usage
	puts "Usage: cewl [OPTIONS] ... <url>

    OPTIONS:
	-h, --help: Show help.
	-k, --keep: Keep the downloaded file.
	-d <x>,--depth <x>: Depth to spider to, default 2.
	-m, --min_word_length: Minimum word length, default 3.
	-x, --max_word_length: Maximum word length, default unset.
	-o, --offsite: Let the spider visit other sites.
	--exclude: A file containing a list of paths to exclude
	--allowed: A regex pattern that path must match to be followed
	-w, --write: Write the output to the file.
	-u, --ua <agent>: User agent to send.
	-n, --no-words: Don't output the wordlist.
	-g <x>, --groups <x>: Return groups of words as well
	--lowercase: Lowercase all parsed words
	--with-numbers: Accept words with numbers in as well as just letters
	--convert-umlauts: Convert common ISO-8859-1 (Latin-1) umlauts (ä-ae, ö-oe, ü-ue, ß-ss)
	-a, --meta: include meta data.
	--meta_file file: Output file for meta data.
	-e, --email: Include email addresses.
	--email_file <file>: Output file for email addresses.
	--meta-temp-dir <dir>: The temporary directory used by exiftool when parsing files, default /tmp.
	-c, --count: Show the count for each word found.
	-v, --verbose: Verbose.
	--debug: Extra debug information.

	Authentication
	--auth_type: Digest or basic.
	--auth_user: Authentication username.
	--auth_pass: Authentication password.

	Proxy Support
	--proxy_host: Proxy host.
	--proxy_port: Proxy port, default 8080.
	--proxy_username: Username for proxy, if required.
	--proxy_password: Password for proxy, if required.

	Headers
	--header, -H: In format name:value - can pass multiple.

    <url>: The site to spider.

"
	exit 0
end

debug = false
verbose = false
ua = nil
url = nil
outfile = nil
email_outfile = nil
meta_outfile = nil
offsite = false
exclude_array = []
allowed_pattern = nil
depth = 2
min_word_length = 3
max_word_length = -1
email = false
meta = false
wordlist = true
groups = -1
meta_temp_dir = "/tmp/"
keep = false
lowercase = false
words_with_numbers = false
convert_umlauts = false
show_count = false
auth_type = nil
auth_user = nil
auth_pass = nil

proxy_host = nil
proxy_port = nil
proxy_username = nil
proxy_password = nil

# headers will be passed in in the format "header: value"
# and there can be multiple
headers = []

strip_css = true
strip_js = true

begin
	opts.each do |opt, arg|
		case opt
			when '--help'
				usage
			when "--lowercase"
				lowercase = true
			when "--with-numbers"
				words_with_numbers = true
			when "--convert-umlauts"
				convert_umlauts = true
			when "--count"
				show_count = true
			when "--meta-temp-dir"
				if !File.directory?(arg)
					puts "\nMeta temp directory is not a directory\n\n"
					exit 1
				end

				if !File.writable?(arg)
					puts "\nThe meta temp directory is not writable\n\n"
					exit 1
				end

				meta_temp_dir = arg
				meta_temp_dir += "/" if meta_temp_dir !~ /.*\/$/
			when "--keep"
				keep = true
			when "--no-words"
				wordlist = false
			when "--meta_file"
				meta_outfile = arg
			when "--meta"
				meta = true
			when "--groups"
				groups = arg.to_i
			when "--email_file"
				email_outfile = arg
			when "--email"
				email = true
			when '--max_word_length'
				max_word_length = arg.to_i
				usage if max_word_length < 1
			when '--min_word_length'
				min_word_length = arg.to_i
				usage if min_word_length < 1
			when '--depth'
				depth = arg.to_i
				usage if depth < 0
			when '--offsite'
				offsite = true
			when '--exclude'
				begin
					tmp_exclude_array = File.readlines(arg)
				rescue => e
					puts "\nUnable to open the excude file\n\n"
					exit 1
				end
				# Have to do this to strip the newline characters from the end
				# of each element in the array
				tmp_exclude_array.each do |line|
					exc = line.strip
					if exc != ""
						exclude_array << line.strip
						# puts "Excluding #{ line.strip}"
					end
				end
			when '--allowed'
				allowed_pattern = Regexp.new(arg)
			when '--ua'
				ua = arg
			when '--debug'
				debug = true
			when '--verbose'
				verbose = true
			when '--write'
				outfile = arg
			when "--header"
				headers << arg
			when "--proxy_password"
				proxy_password = arg
			when "--proxy_username"
				proxy_username = arg
			when "--proxy_host"
				proxy_host = arg
			when "--proxy_port"
				proxy_port = arg.to_i
			when "--auth_pass"
				auth_pass = arg
			when "--auth_user"
				auth_user = arg
			when "--auth_type"
				if arg =~ /(digest|basic)/i
					auth_type = $1.downcase
					if auth_type == "digest"
						begin
							require "net/http/digest_auth"
						rescue LoadError => e
							# Catch error and provide feedback on installing gem
							puts "\nError: To use digest auth you require the net-http-digest_auth gem\n"
							puts "\t Use: 'gem install net-http-digest_auth'\n\n"
							exit 2
						end
					end
				else
					puts "\nInvalid authentication type, please specify either basic or digest\n\n"
					exit 1
				end
		end
	end
rescue => e
	# puts e
	usage
end

if auth_type && (auth_user.nil? || auth_pass.nil?)
	puts "\nIf using basic or digest auth you must provide a username and password\n\n"
	exit 1
end

if auth_type.nil? && (!auth_user.nil? || !auth_pass.nil?)
	puts "\nAuthentication details provided but no mention of basic or digest\n\n"
	exit 1
end

if ARGV.length != 1
	puts "\nMissing URL argument (try --help)\n\n"
	exit 1
end

url = ARGV.shift

# Must have protocol
url = "http://#{url}" if url !~ /^http(s)?:\/\//

# Taking this back out again. Can't remember why it was put in but have found problems
# with it in and none with it out so getting rid of it.
#
# The spider doesn't work properly if there isn't a / on the end
#if url !~ /\/$/
#	url = "#{url}/"
#end

group_word_hash = {}
word_hash = {}
email_arr = []
url_stack = Tree.new
url_stack.debug = debug
url_stack.max_depth = depth
usernames = Array.new()

# Do the checks here so we don't do all the processing then find we can't open the file
if outfile
	begin
		outfile_file = File.new(outfile, "w")
	rescue
		puts "\nCouldn't open the output file for writing\n\n"
		exit 2
	end
else
	outfile_file = $stdout
end

if email_outfile && email
	begin
		email_outfile_file = File.new(email_outfile, "w")
	rescue
		puts "\nCouldn't open the email output file for writing\n\n"
		exit 2
	end
else
	email_outfile_file = outfile_file
end

if meta_outfile && meta
	begin
		meta_outfile_file = File.new(meta_outfile, "w")
	rescue
		puts "\nCouldn't open the metadata output file for writing\n\n"
		exit 2
	end
else
	meta_outfile_file = outfile_file
end

catch :ctrl_c do
	begin
		puts "Starting at #{url}" if verbose

		MySpider.proxy(proxy_host, proxy_port, proxy_username, proxy_password) if proxy_host
		MySpider.auth_creds(auth_type, auth_user, auth_pass) if auth_type
		MySpider.headers(headers)
		MySpider.verbose(verbose)
		MySpider.debug(debug)

		MySpider.start_at(url) do |s|
			s.headers['User-Agent'] = ua if ua

			s.add_url_check do |a_url|
				puts "Checking page #{a_url}" if debug
				allow = true

				# Extensions to ignore
				if a_url =~ /(\.zip$|\.gz$|\.zip$|\.bz2$|\.png$|\.gif$|\.jpg$|^#)/
					puts "Ignoring internal link or graphic: #{a_url}" if verbose
					allow = false
				else
					if /^mailto:(.*)/i.match(a_url)
						if email
							email_arr << $1
							puts "Found #{$1} on page #{a_url}" if verbose
						end
						allow = false
					else
						a_url_parsed = URI.parse(a_url)
						if !offsite
							url_parsed = URI.parse(url)
							puts "Comparing #{a_url} with #{url}" if debug

							# Make sure the host, port and scheme matches (else its offsite)
							allow = (a_url_parsed.host == url_parsed.host) && (a_url_parsed.port == url_parsed.port) && (a_url_parsed.scheme == url_parsed.scheme) ? true : false

							puts "Offsite link, not following: #{a_url}" if !allow && verbose
						else
							puts "Allowing offsite links" if @debug
						end

						puts "Found: #{a_url_parsed.path}" if @debug

						if exclude_array.include?(a_url_parsed.request_uri)
							puts "Excluding page: #{a_url_parsed.request_uri}" if verbose
							allow = false
						end

						if allowed_pattern && !a_url_parsed.path.match(allowed_pattern)
							puts "Excluding path: #{a_url_parsed.path} based on allowed pattern" if verbose
							allow = false
						end
					end
				end
				allow
			end

			# This was :success so only the content from a 200 was processed.
			# Updating it to :every so that the content of all pages gets processed
			# so you can grab things off 404s or text leaked on redirect and error pages.

			s.on :every do |a_url, resp, prior_url|
				if verbose
					if prior_url.nil?
						puts "Visiting: #{a_url}, got response code #{resp.code}"
					else
						puts "Visiting: #{a_url} referred from #{prior_url}, got response code #{resp.code}"
					end
				end

				# May want 0-9 in here as well in the future but for now limit it to a-z so
				# you can't sneak any nasty characters in
				if /.*\.([a-z]+)(\?.*$|$)/i.match(a_url)
					file_extension = $1
				else
					file_extension = ''
				end

				# Don't get words from these file types. Most will have been blocked by the url_check function but
				# some are let through, such as .css, so that they can be checked for email addresses

				# This is a bad way to do this but it is either white or black list extensions and
				# the list of either is quite long, may as well black list and let extra through
				# that can then be weeded out later than stop things that could be useful

				#if file_extension =~ /^((doc|dot|ppt|pot|xls|xlt|pps)[xm]?)|(ppam|xlsb|xlam|pdf|zip|gz|zip|bz2|css|png|gif|jpg|#)$/
				if file_extension =~ /^((doc|dot|ppt|pot|xls|xlt|pps)[xm]?)|(ppam|xlsb|xlam|pdf|zip|gz|zip|bz2|png|gif|jpg|#)$/
					if meta
						begin
							if keep && file_extension =~ /^((doc|dot|ppt|pot|xls|xlt|pps)[xm]?)|(ppam|xlsb|xlam|pdf|zip|gz|zip|bz2)$/
								if /.*\/(.*)$/.match(a_url)
									output_filename = meta_temp_dir + $1
									puts "Keeping #{output_filename}" if verbose
								else
									# Shouldn't ever get here as the regex above should always be able to pull the filename out of the URL,
									# ...but just in case

									# Maybe look at doing this to make the temp name
									# require "tempfile"
									# Dir::Tmpname.make_tmpname "a", "b"
									#	=> "a20150707-8694-hrrxr4-b"

									output_filename = "#{meta_temp_dir}cewl_tmp"
									output_filename += ".#{file_extension}" unless file_extension.empty?
								end
							else
								output_filename = "#{meta_temp_dir}cewl_tmp"
								output_filename += ".#{file_extension}" unless file_extension.empty?
							end

							out = File.new(output_filename, "wb")
							out.print(resp.body)
							out.close

							meta_data = process_file(output_filename, verbose)
							usernames += meta_data if (meta_data != nil)
						rescue => e
							puts "\nCouldn't open the meta temp file for writing - #{e.inspect}\n\n"
							exit 2
						end
					end
				else
					html = resp.body.to_s.force_encoding("UTF-8")
					# This breaks on this site http://www.spisa.nu/recept/ as the
					# replace replaces some of the important characters. Needs a fix
					html.encode!('UTF-16', 'UTF-8', :invalid => :replace, :replace => '')
					html.encode!('UTF-8', 'UTF-16')

					dom = Nokogiri.HTML(html)
					dom.css('script').remove if strip_js
					dom.css('style').remove if strip_css
					body = dom.to_s

					# Get meta data
					if /.*<meta.*description.*content\s*=[\s'"]*(.*)/i.match(body)
						description = $1
						body += description.gsub(/[>"\/']*/, "")
					end

					if /.*<meta.*keywords.*content\s*=[\s'"]*(.*)/i.match(body)
						keywords = $1
						body += keywords.gsub(/[>"\/']*/, "")
					end

					puts body if debug

					# This bit will not normally fire as all JavaScript is stripped out
					# by the Nokogiri remove a few lines before this.
					#
					# The code isn't perfect but will do a rough job of working out
					# pages from relative location links
					while /(location.href\s*=\s*["']([^"']*)['"];)/i.match(body)
						full_match = $1
						j_url = $2

						puts "Javascript redirect found #{j_url}" if verbose

						re = Regexp.escape(full_match)
						body.gsub!(/#{re}/, "")

						if j_url !~ /https?:\/\//i
							parsed = URI.parse(a_url)
							protocol = parsed.scheme
							host = parsed.host

							domain = "#{protocol}://#{host}"

							j_url = domain + j_url
							j_url += $1 if j_url[0] == "/" && parsed.path =~ /(.*)\/.*/

							puts "Relative URL found, adding domain to make #{j_url}" if verbose
						end

						x = {a_url => j_url}
						url_stack.push x
					end

					# Strip comment tags
					body.gsub!(/<!--/, "")
					body.gsub!(/-->/, "")

					# If you want to add more attribute names to include, just add them to this array
					attribute_names = [
							"alt",
							"title",
					]

					attribute_text = ''

					attribute_names.each { |attribute_name|
						body.gsub!(/#{attribute_name}="([^"]*)"/) { |attr| attribute_text += "#{$1} " }
					}

					if verbose and attribute_text
						puts "Attribute text found:"
						puts attribute_text
						puts
					end

					body += " #{attribute_text}"

					# Strip html tags
					words = body.gsub(/<\/?[^>]*>/, "")

					# Check if this is needed
					words.gsub!(/&[a-z]*;/, "")

					begin
						#if file_extension !~ /^((doc|dot|ppt|pot|xls|xlt|pps)[xm]?)|(ppam|xlsb|xlam|pdf|zip|gz|zip|bz2|css|png|gif|jpg|#)$/
						begin
							if email
								# Split the file down based on the email address regexp
								#words.gsub!(/\b([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4})\b/i)
								#p words

								# If you want to pull email addresses from the contents of files found, such as word docs then move
								# this block outside the if statement
								# I've put it in here as some docs contain email addresses that have nothing to do with the target
								# so give false positive type results
								words.each_line do |word|
									while /\b([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4})\b/i.match(word)
										puts "Found #{$1} on page #{a_url}" if verbose
										email_arr << $1
										word = word.gsub(/#{$1}/, "")
									end
								end
							end
						rescue => e
							puts "\nThere was a problem generating the email list"
							puts "Error: #{e.inspect}"
							puts e.backtrace
						end

						if wordlist
							# Lowercase all parsed words
							if lowercase then
								words.downcase!
							end
							# Remove any symbols
							if words_with_numbers then
								words.gsub!(/[^[[:alnum:]]]/i, " ")
							else
								words.gsub!(/[^[[:alpha:]]]/i, " ")
							end

							if convert_umlauts then
								words.gsub!(/[äöüßÄÖÜ]/, "ä" => "ae", "ö" => "oe", "ü" => "ue", "ß" => "ss", "Ä" => "Ae", "Ö" => "Oe", "Ü" => "Ue")
							end

							# Add to the array
							group_words = []
							words.split(" ").each do |word|
								if word.length >= min_word_length and (max_word_length == -1 or word.length <= max_word_length)
									word_hash[word] = 0 if !word_hash.has_key?(word)
									word_hash[word] += 1
								end
								if (groups > 0)
									group_words.push (word)
									if (group_words.length() > groups)
										group_words.shift()
									end
									if (group_words.length() == groups)
										joined = group_words.join(" ")
										group_word_hash[joined] = 0 if !group_word_hash.has_key?(joined)
										group_word_hash[joined] += 1
									end
								end
							end
						end
						#end
					rescue => e
						puts "\nThere was a problem handling word generation"
						puts "Error: #{e.inspect}"
						puts e.backtrace
					end
				end
			end
			s.store_next_urls_with url_stack
		end
	rescue Errno::ENOENT
		puts "\nInvalid URL specified (#{url})\n\n"
		exit 2
	rescue => e
		puts "\nCouldn't access the site (#{url})\n"
		puts "Error: #{e.inspect}"
		puts "Error: #{e.backtrace}"
		exit 2
	end
end

puts "End of main loop" if debug

if wordlist
	if verbose
		if outfile.nil?
			puts "Words found\n"
		else
			puts "Writing words to file\n"
		end
	end

	sorted_wordlist = word_hash.sort_by do |word, count|
		-count
	end

	sorted_wordlist.each do |word, count|
		if show_count
			outfile_file.puts "#{word}, #{count.to_s}"
		else
			outfile_file.puts word
		end
	end
end

if groups > 0
	if verbose
		if outfile.nil?
			puts "Groups of words found\n"
		else
			puts "Writing groups of words to file\n"
		end
	end

	sorted_wordlist = group_word_hash.sort_by do |word, count|
		-count
	end

	sorted_wordlist.each do |word, count|
		if show_count
			outfile_file.puts "#{word}, #{count.to_s}"
		else
			outfile_file.puts word
		end
	end
end

puts "End of wordlist loop" if debug

if email
	if email_arr.length == 0
		puts "No email addresses found" if verbose
	else
		puts "Dumping email addresses to file" if verbose

		email_arr.delete_if { |x| x.chomp.empty? }
		email_arr.uniq!
		email_arr.sort!

		outfile_file.puts if (wordlist || verbose) && email_outfile.nil?

		if email_outfile.nil?
			outfile_file.puts "Email addresses found"
			outfile_file.puts "---------------------"
			outfile_file.puts email_arr.join("\n")
		else
			email_outfile_file.puts email_arr.join("\n")
		end
	end
end

puts "End of email loop" if debug

if meta
	if usernames.length == 0
		puts "No meta data found" if verbose
	else
		puts "Dumping meta data to file" if verbose
		usernames.delete_if { |x| x.chomp.empty? }
		usernames.uniq!
		usernames.sort!

		outfile_file.puts if (email||wordlist) && meta_outfile.nil?
		if meta_outfile.nil?
			outfile_file.puts "Meta data found"
			outfile_file.puts "---------------"
			outfile_file.puts usernames.join("\n")
		else
			meta_outfile_file.puts usernames.join("\n")
		end
	end
end

puts "End of meta loop" if debug

meta_outfile_file.close if meta_outfile
email_outfile_file.close if email_outfile
outfile_file.close if outfile
