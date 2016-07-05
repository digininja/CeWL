#!/usr/bin/env ruby

# == FAB: Files Already Bagged
#
# This script can be ran against files already
# downloaded from a target site to generate a list
# of usernames and email addresses based on meta
# data contained within them.
#
# To see a list of file types which can be processed
# see cewl_lib.rb
#
# == Usage
#
# fab [OPTION] ... filename/list
#
# -h, --help:
#    show help
#
# -v
#    verbose
#
# filename/list: the file or list of files to check
#
# Author:: Robin Wood (robin@digininja.org)
# Copyright:: Copyright (c) Robin Wood 2016
# Licence:: GPL
#

require "rubygems"
require 'getoptlong'
require "./cewl_lib.rb"

opts = GetoptLong.new(
	[ '--help', '-h', GetoptLong::NO_ARGUMENT ],
	[ "-v" , GetoptLong::NO_ARGUMENT ]
)

def usage
	puts"xx

Usage: xx [OPTION] ... filename/list
	-h, --help: show help
	-v: verbose
	
	filename/list: the file or list of files to check

"
	exit
end

verbose=false

begin
	opts.each do |opt, arg|
		case opt
		when '--help'
			usage
		when '-v'
			verbose=true
		end
	end
rescue
	usage
end

if ARGV.length < 1
	puts "Missing filename/list (try --help)"
	exit 0
end

meta_data=[]

ARGV.each { |param|
	data=process_file(param, verbose)
	if(data!=nil)
		meta_data+=data
	end
}

meta_data.delete_if { |x| x.chomp==""}
meta_data.uniq!
meta_data.sort!
if meta_data.length==0
	puts "No data found\n"
else
	puts meta_data.join("\n")
end
