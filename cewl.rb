#!/usr/bin/env ruby
#encoding: UTF-8

# == CeWL: Custom Word List Generator
#
# CeWL will spider a target site and generate up to three lists:
#
# * A word list of all unique words found on the target site
# * A list of all email addresses found in mailto links
# * A list of usernames/author details from meta data found in any documents on the site
#
# == Usage
#
# cewl [OPTION] ... URL
#
# -h, --help:
#	show help
#
# --depth x, -d x:
#	depth to spider to, default 2
#
# --min_word_length, -m:
#	minimum word length, default 3
#
# --email file, -e
# --email_file file: 
#	include any email addresses found duing the spider, email_file is optional output file, if 
#	not included the output is added to default output
#
# --meta file, -a
# --meta_file file:
#	include any meta data found during the spider, meta_file is optional output file, if 
#	not included the output is added to default output
#
# --no-words, -n
#	don't output the wordlist
#
# --offsite, -o:
#	let the spider visit other sites
#
# --write, -w file:
#	write the words to the file
#
# --ua, -u user-agent:
#	useragent to send
#
# --meta-temp-dir directory:
#	the temporary directory used by exiftool when parsing files, default /tmp
#
# --keep, -k:
#   keep the documents that are downloaded
#
# --count, -c:
#   show the count for each of the words found
#
# -v
#	verbose
#
# URL: The site to spider.
#
# Author:: Robin Wood (robin@digi.ninja)
# Copyright:: Copyright (c) Robin Wood 2014
# Licence:: CC-BY-SA 2.0 or GPL-3+
#

VERSION = "5.1"

puts"CeWL #{VERSION} Robin Wood (robin@digi.ninja) (http://digi.ninja)"
puts

begin
	require 'getoptlong'
	require 'spider'
	require 'nokogiri'
	require 'net/http'
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

require './cewl_lib'

# Doing this so I can override the allowed? fuction which normally checks
# the robots.txt file
class MySpider<Spider
	@@proxy_host = nil
	@@proxy_port = nil
	@@proxy_username = nil
	@@proxy_password = nil

	@@auth_type = nil
	@@auth_user = nil
	@@auth_password = nil
	@@verbose = false

	def self.proxy (host, port = nil, username = nil, password = nil)
		@@proxy_host = host
		port = 8080 if port.nil?
		@@proxy_port = port
		@@proxy_username = username
		@@proxy_password = password
	end

	def self.auth_creds (type, user, password)
		@@auth_type = type
		@@auth_user = user
		@@auth_password = password
	end

	def self.verbose (val)
		@@verbose = val
	end

	# Create an instance of MySpiderInstance rather than SpiderInstance
	def self.start_at(a_url, &block)
		rules = RobotRules.new('Ruby Spider 1.0')
		a_spider = MySpiderInstance.new({nil => a_url}, [], rules, [])
		a_spider.auth_type = @@auth_type
		a_spider.auth_user = @@auth_user
		a_spider.auth_password = @@auth_password

		a_spider.proxy_host = @@proxy_host
		a_spider.proxy_port = @@proxy_port
		a_spider.proxy_username = @@proxy_username
		a_spider.proxy_password = @@proxy_password

		a_spider.verbose = @@verbose
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

	attr_writer :proxy_host
	attr_writer :proxy_port
	attr_writer :proxy_username
	attr_writer :proxy_password

	attr_writer :verbose

	# Force all files to be allowed
	# Normally the robots.txt file will be honoured
	def allowed?(a_url, parsed_url)
		true
	end
	def start! #:nodoc: 
		interrupted = false
		trap("SIGINT") { interrupted = true } 
		begin
			next_urls = @next_urls.pop
			tmp_n_u = {}
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
							#puts 'pushing ' + a_next_url
							@next_urls.push a_url => a_next_url
						end
						#exit if interrupted
					end
					@teardown.call(a_url) unless @teardown.nil?
					exit if interrupted
				end
			end
		end while !@next_urls.empty?
	end

	def get_page(uri, &block) #:nodoc:
		@seen << uri
		
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
					puts "Failed to connect to the proxy"
					exit
				end
			end
			
			req = Net::HTTP::Get.new(uri.request_uri, @headers)
			
			if !@auth_type.nil?
				case @auth_type
					when "digest"
						uri.user = @auth_user
						uri.password = @auth_password

						res = http.request req

						if not res['www-authenticate'].nil?
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
				#puts "redirect url"
				base_url = uri.to_s[0, uri.to_s.rindex('/')]
				new_url = URI.parse(construct_complete_url(base_url,res['Location']))

				# If auth is used then a name:pass@ gets added, this messes the tree
				# up so easiest to just remove it
				current_uri = uri.to_s.gsub(/:\/\/[^:]*:[^@]*@/, "://")
				@next_urls.push current_uri => new_url.to_s
			elsif res.code == "401"
				puts "Authentication required, can't continue on this branch - #{uri}" if @verbose
			else
				block.call(res)
			end
		rescue  => e
			puts "Unable to connect to the site, run in verbose mode for more information"
			if @verbose
				puts
				puts"The following error may help:"
				puts e.to_s
				puts e.backtrace
				puts "Caller"
				puts caller
			end
			exit
		end
	end
	# overriding so that I can get it to ingore direct names - i.e. #name
	def construct_complete_url(base_url, additional_url, parsed_additional_url = nil) #:nodoc:
		if additional_url =~ /^#/
			return nil
		end
		parsed_additional_url ||= URI.parse(additional_url)
		case parsed_additional_url.scheme
			when nil
				u = base_url.is_a?(URI) ? base_url : URI.parse(base_url)
				if additional_url[0].chr == '/'
					"#{u.scheme}://#{u.host}#{additional_url}"
				elsif u.path.nil? || u.path == ''
					"#{u.scheme}://#{u.host}/#{additional_url}"
				elsif u.path[0].chr == '/'
					"#{u.scheme}://#{u.host}#{u.path}/#{additional_url}"
				else
					"#{u.scheme}://#{u.host}/#{u.path}/#{additional_url}"
				end
			else
				additional_url
		end
	end

	# Overriding the original spider one as it doesn't find hrefs very well
	def generate_next_urls(a_url, resp) #:nodoc:
		web_page = resp.body
		if URI.parse(a_url).path == ""
			base_url = a_url
		else
			base_url = a_url[0, a_url.rindex('/')]
		end

		doc = Nokogiri::HTML(web_page)
		links = doc.css('a').map{ |a| a['href'] }
		links.map do |link|
			begin
				if link.nil?
					nil
				else
					begin
						parsed_link = URI.parse(link)
						if parsed_link.fragment == '#'
							nil
						else
							construct_complete_url(base_url, link, parsed_link)
						end
					rescue
						nil
					end
				end
			rescue => e
				puts "There was an error generating URL list"
				puts "Error: " + e.inspect
				puts e.backtrace
				exit
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
		@key=key
		@value=value
		@depth=depth
		@visited=false
	end

	def to_s
		if key==nil
			return "key=nil value="+@value+" depth="+@depth.to_s+" visited="+@visited.to_s
		else
			return "key="+@key+" value="+@value+" depth="+@depth.to_s+" visited="+@visited.to_s
		end
	end
	def to_url_hash
		return({@key=>@value})
	end
end

# A tree structure
class Tree
	attr :data
	@max_depth
	@children

	# Get the maximum depth the tree can grow to
	def max_depth
		@max_depth
	end

	# Set the max depth the tree can grow to
	def max_depth=(val)
		@max_depth=Integer(val)
	end
	
	# As this is used to work out if there are any more nodes to process it isn't a true empty
	def empty?
		if !@data.visited
			return false
		else
			@children.each { |node|
				if !node.data.visited
					return false
				end
			}
		end
		return true
	end

	# The constructor
	def initialize(key=nil, value=nil, depth=0)
		@data=TreeNode.new(key,value,depth)
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
			@data.visited=true
			return @data.to_url_hash
		else
			@children.each { |node|
				if !node.data.visited
					node.data.visited=true
					return node.data.to_url_hash
				end
			}
		end
		return nil
	end

	# Push an item onto the tree
	def push(value)
		key=value.keys.first
		value=value.values_at(key).first

		if key==nil
			@data=TreeNode.new(key,value,0)
		else
			# if the depth is 0 then don't add anything to the tree
			if @max_depth == 0
				return
			end
			if key==@data.value
				child=Tree.new(key,value, @data.depth+1)
				@children << child
			else
				@children.each { |node|
					if node.data.value==key && node.data.depth<@max_depth
						child=Tree.new(key,value, node.data.depth+1)
						@children << child
					end
				}
			end
		end
	end
end

opts = GetoptLong.new(
	[ '--help', '-h', GetoptLong::NO_ARGUMENT ],
	[ '--keep', '-k', GetoptLong::NO_ARGUMENT ],
	[ '--depth', '-d', GetoptLong::OPTIONAL_ARGUMENT ],
	[ '--min_word_length', "-m" , GetoptLong::REQUIRED_ARGUMENT ],
	[ '--no-words', "-n" , GetoptLong::NO_ARGUMENT ],
	[ '--offsite', "-o" , GetoptLong::NO_ARGUMENT ],
	[ '--write', "-w" , GetoptLong::REQUIRED_ARGUMENT ],
	[ '--ua', "-u" , GetoptLong::REQUIRED_ARGUMENT ],
	[ '--meta-temp-dir', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--meta_file', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--email_file', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--meta', "-a" , GetoptLong::NO_ARGUMENT ],
	[ '--email', "-e" , GetoptLong::NO_ARGUMENT ],
	[ '--count', '-c', GetoptLong::NO_ARGUMENT ],
	[ '--auth_user', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--auth_pass', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--auth_type', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--proxy_host', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--proxy_port', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--proxy_username', GetoptLong::REQUIRED_ARGUMENT ],
	[ '--proxy_password', GetoptLong::REQUIRED_ARGUMENT ],
	[ "--verbose", "-v" , GetoptLong::NO_ARGUMENT ]
)

# Display the usage
def usage
	puts "Usage: cewl [OPTION] ... URL
	--help, -h: show help
	--keep, -k: keep the downloaded file
	--depth x, -d x: depth to spider to, default 2
	--min_word_length, -m: minimum word length, default 3
	--offsite, -o: let the spider visit other sites
	--write, -w file: write the output to the file
	--ua, -u user-agent: useragent to send
	--no-words, -n: don't output the wordlist
	--meta, -a include meta data
	--meta_file file: output file for meta data
	--email, -e include email addresses
	--email_file file: output file for email addresses
	--meta-temp-dir directory: the temporary directory used by exiftool when parsing files, default /tmp
	--count, -c: show the count for each word found

	Authentication
	--auth_type: digest or basic
	--auth_user: authentication username
	--auth_pass: authentication password
	
	Proxy Support
	--proxy_host: proxy host
	--proxy_port: proxy port, default 8080
	--proxy_username: username for proxy, if required
	--proxy_password: password for proxy, if required

	--verbose, -v: verbose

	URL: The site to spider.

"
	exit
end

verbose=false
ua=nil
url = nil
outfile = nil
email_outfile = nil
meta_outfile = nil
offsite = false
depth = 2
min_word_length=3
email=false
meta=false
wordlist=true
meta_temp_dir="/tmp/"
keep=false
show_count = false
auth_type = nil
auth_user = nil
auth_pass = nil

proxy_host = nil
proxy_port = nil
proxy_username = nil
proxy_password = nil

strip_css = true
strip_js = true

begin
	opts.each do |opt, arg|
		case opt
		when '--help'
			usage
		when "--count"
			show_count = true
		when "--meta-temp-dir"
			if !File.directory?(arg)
				puts "Meta temp directory is not a directory\n"
				exit
			end
			if !File.writable?(arg)
				puts "The meta temp directory is not writable\n"
				exit
			end
			meta_temp_dir=arg
			if meta_temp_dir !~ /.*\/$/
				meta_temp_dir+="/"
			end
		when "--keep"
			keep=true
		when "--no-words"
			wordlist=false
		when "--meta_file"
			meta_outfile = arg
		when "--meta"
			meta=true
		when "--email_file"
			email_outfile = arg
		when "--email"
			email=true
		when '--min_word_length'
			min_word_length=arg.to_i
			if min_word_length<1
				usage
			end
		when '--depth'
			depth=arg.to_i
			if depth < 0
				usage
			end
		when '--offsite'
			offsite=true
		when '--ua'
			ua=arg
		when '--verbose'
			verbose=true
		when '--write'
			outfile=arg
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
				auth_type=$1.downcase
				if auth_type == "digest"
					begin
						require "net/http/digest_auth"
					rescue LoadError => e
						# catch error and prodive feedback on installing gem
						puts "\nError: To use digest auth you require the net-http-digest_auth gem, to install it use:\n\n"
						puts "\t\"gem install net-http-digest_auth\"\n\n"
						exit
					end
				end
			else
				puts "Invalid authentication type, please specify either basic or digest"
				exit
			end
		end
	end
rescue
	usage
end

if !auth_type.nil? and (auth_user.nil? or auth_pass.nil?)
	puts "If using basic or digest auth you must provide a username and password\n\n"
	exit
end

if auth_type.nil? and (!auth_user.nil? or !auth_pass.nil?)
	puts "Authentication details provided but no mention of basic or digest"
	exit
end

if ARGV.length != 1
	puts "Missing url argument (try --help)"
	exit 0
end

url = ARGV.shift

# Must have protocol
if url !~ /^http(s)?:\/\//
	url="http://"+url
end

# The spider doesn't work properly if there isn't a / on the end
if url !~ /\/$/
#	Commented out for Yori
#	url=url+"/"
end

word_hash = {}
email_arr=[]
url_stack=Tree.new
url_stack.max_depth=depth
usernames=Array.new()

# Do the checks here so we don't do all the processing then find we can't open the file
if !outfile.nil?
	begin
		outfile_file=File.new(outfile,"w")
	rescue
		puts "Couldn't open the output file for writing"
		exit
	end
else
	outfile_file=$stdout
end

if !email_outfile.nil? and email
	begin
		email_outfile_file=File.new(email_outfile,"w")
	rescue
		puts "Couldn't open the email output file for writing"
		exit
	end
else
	email_outfile_file = outfile_file
end

if !meta_outfile.nil? and email
	begin
		meta_outfile_file=File.new(meta_outfile,"w")
	rescue
		puts "Couldn't open the metadata output file for writing"
		exit
	end
else
	meta_outfile_file = outfile_file
end

begin
	if verbose
		puts "Starting at " + url
	end

	if !proxy_host.nil?
		MySpider.proxy(proxy_host, proxy_port, proxy_username, proxy_password)
	end

	if !auth_type.nil?
		MySpider.auth_creds(auth_type, auth_user, auth_pass)
	end
	MySpider.verbose(verbose)
	
	MySpider.start_at(url) do |s|
		if ua!=nil
			s.headers['User-Agent'] = ua
		end

		s.add_url_check do |a_url|
			#puts "checking page " + a_url
			allow=true
			# Extensions to ignore
			if a_url =~ /(\.zip$|\.gz$|\.zip$|\.bz2$|\.png$|\.gif$|\.jpg$|^#)/
				if verbose
					puts "Ignoring internal link or graphic: "+a_url
				end
				allow=false
			else
				if /^mailto:(.*)/i.match(a_url)
					if email
						email_arr<<$1
						if verbose
							puts "Found #{$1} on page #{a_url}"
						end
					end
					allow=false
				else
					if !offsite
						a_url_parsed = URI.parse(a_url)
						url_parsed = URI.parse(url)
#							puts 'comparing ' + a_url + ' with ' + url

						allow = (a_url_parsed.host == url_parsed.host)

						if !allow && verbose
							puts "Offsite link, not following: "+a_url
						end
					end
				end
			end
			allow
		end

		s.on :success do |a_url, resp, prior_url|

			if verbose
				if prior_url.nil?
					puts "Visiting: #{a_url}, got response code #{resp.code}"
				else
					puts "Visiting: #{a_url} referred from #{prior_url}, got response code #{resp.code}"
				end
			end
			html=resp.body.to_s.force_encoding("UTF-8")
			html.encode!('UTF-16', 'UTF-8', :invalid => :replace, :replace => '')
			html.encode!('UTF-8', 'UTF-16')
			
			dom = Nokogiri.HTML(html)
			dom.css('script').remove if strip_js
			dom.css('style').remove if strip_css
			body = dom.to_s

			# get meta data
			if /.*<meta.*description.*content\s*=[\s'"]*(.*)/i.match(body)
				description=$1
				body += description.gsub(/[>"\/']*/, "") 
			end 

			if /.*<meta.*keywords.*content\s*=[\s'"]*(.*)/i.match(body)
				keywords=$1
				body += keywords.gsub(/[>"\/']*/, "") 
			end 

#				puts body
#				while /mailto:([^'">]*)/i.match(body)
#					email_arr<<$1
#					if verbose
#						puts "Found #{$1} on page #{a_url}"
#					end
#				end 

			while /(location.href\s*=\s*["']([^"']*)['"];)/i.match(body)
				full_match = $1
				j_url = $2
				if verbose
					puts "Javascript redirect found " + j_url
				end

				re = Regexp.escape(full_match)

				body.gsub!(/#{re}/,"")

				if j_url !~ /https?:\/\//i

# Broken, needs real domain adding here
# http://docs.seattlerb.org/net-http-digest_auth/Net/HTTP/DigestAuth.html

					domain = "http://ninja.dev/"
					j_url = domain + j_url
					if verbose
						puts "Relative URL found, adding domain to make " + j_url
					end
				end

				x = {a_url=>j_url}
				url_stack.push x
			end

			# strip comment tags
			body.gsub!(/<!--/, "")
			body.gsub!(/-->/, "")

			# If you want to add more attribute names to include, just add them to this array
			attribute_names = [
								"alt",
								"title",
							]

			attribute_text = ""

			attribute_names.each { |attribute_name|
				body.gsub!(/#{attribute_name}="([^"]*)"/) { |attr| attribute_text += $1 + " " }
			}

			if verbose
				puts "Attribute text found:"
				puts attribute_text
				puts
			end

			body += " " + attribute_text

			# strip html tags
			words=body.gsub(/<\/?[^>]*>/, "") 

			# check if this is needed
			words.gsub!(/&[a-z]*;/, "") 

			# may want 0-9 in here as well in the future but for now limit it to a-z so
			# you can't sneak any nasty characters in
			if /.*\.([a-z]+)(\?.*$|$)/i.match(a_url)
				file_extension=$1
			else
				file_extension=""
			end

			if meta
				begin
					if keep and file_extension =~ /^((doc|dot|ppt|pot|xls|xlt|pps)[xm]?)|(ppam|xlsb|xlam|pdf|zip|gz|zip|bz2)$/
						if /.*\/(.*)$/.match(a_url)
							output_filename=meta_temp_dir+$1
							if verbose
								puts "Keeping " + output_filename
							end
						else
							# shouldn't ever get here as the regex above should always be able to pull the filename out of the url, 
							# but just in case
							output_filename=meta_temp_dir+"cewl_tmp"
							output_filename += "."+file_extension unless file_extension==""
						end
					else
						output_filename=meta_temp_dir+"cewl_tmp"
						output_filename += "."+file_extension unless file_extension==""
					end
					out=File.new(output_filename, "w")
					out.print(resp.body)
					out.close

					meta_data=process_file(output_filename, verbose)
					if(meta_data!=nil)
						usernames+=meta_data
					end
				rescue => e
					puts "Couldn't open the meta temp file for writing - " + e.inspect
					exit
				end
			end

			# don't get words from these file types. Most will have been blocked by the url_check function but
			# some are let through, such as .css, so that they can be checked for email addresses

			# this is a bad way to do this but it is either white or black list extensions and 
			# the list of either is quite long, may as well black list and let extra through
			# that can then be weeded out later than stop things that could be useful
			begin
				if file_extension !~ /^((doc|dot|ppt|pot|xls|xlt|pps)[xm]?)|(ppam|xlsb|xlam|pdf|zip|gz|zip|bz2|css|png|gif|jpg|#)$/
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
									if verbose
										puts "Found #{$1} on page #{a_url}"
									end
									email_arr<<$1
									word=word.gsub(/#{$1}/, "")
								end
							end
						end
					rescue => e
						puts "There was a problem generating the email list"
						puts "Error: " + e.inspect
						puts e.backtrace
					end
				
					if wordlist
						# remove any symbols
						words.gsub!(/[^[:alpha:]]/i," ")
						# add to the array
						words.split(" ").each do |word|
							if word.length >= min_word_length
								if !word_hash.has_key?(word)
									word_hash[word] = 0
								end
								word_hash[word] += 1
							end
						end
					end
				end
			rescue => e
				puts "There was a problem handling word generation"
				puts "Error: " + e.inspect
			end
		end
		s.store_next_urls_with url_stack

	end
rescue Errno::ENOENT
	puts "Invalid URL specified"
	puts
	exit
rescue => e
	puts "Couldn't access the site"
	puts
	puts "Error: " + e.inspect
	puts e.backtrace
	exit
end

#puts "end of main loop"

if wordlist
	puts "Words found\n\n" if verbose

	sorted_wordlist = word_hash.sort_by do |word, count| -count end
	sorted_wordlist.each do |word, count|
		if show_count
			outfile_file.puts word + ', ' + count.to_s
		else
			outfile_file.puts word
		end
	end
end

#puts "end of wordlist loop"

if email
	puts "Dumping email addresses to file" if verbose

	email_arr.delete_if { |x| x.chomp==""}
	email_arr.uniq!
	email_arr.sort!

	if (wordlist||verbose) && email_outfile.nil?
		outfile_file.puts
	end
	if email_outfile.nil?
		outfile_file.puts "Email addresses found"
		outfile_file.puts email_arr.join("\n")
	else
		email_outfile_file.puts email_arr.join("\n")
	end
end

#puts "end of email loop"

if meta
	puts "Dumping meta data to file" if verbose
	usernames.delete_if { |x| x.chomp==""}
	usernames.uniq!
	usernames.sort!

	if (email||wordlist) && meta_outfile.nil?
		outfile_file.puts
	end
	if meta_outfile.nil?
		outfile_file.puts "Meta data found"
		outfile_file.puts usernames.join("\n")
	else
		meta_outfile_file.puts usernames.join("\n")
	end
end

#puts "end of meta loop"

if meta_outfile!=nil
	meta_outfile_file.close
end

if email_outfile!=nil
	email_outfile_file.close
end

if outfile!=nil
	outfile_file.close
end
