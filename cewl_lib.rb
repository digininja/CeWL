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
# Author:: Robin Wood (dninja@gmail.com)
# Copyright:: Copyright (c) Robin Wood 2016
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
		Zip::ZipFile.open(docx_file) { |zipfile|
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
