CeWL - Custom Word List generator
=================================

Copyright(c) 2016, Robin Wood <robin@digininja.org>

Based on a discussion on PaulDotCom (episode 129) about creating custom word lists
spidering a targets website and collecting unique words I decided to write
CeWL, the Custom Word List generator. CeWL is a ruby app which spiders a
given URL to a specified depth, optionally following external links, and
returns a list of words which can then be used for password crackers such
as John the Ripper.

By default, CeWL sticks to just the site you have specified and will go to a
depth of 2 links, this behaviour can be changed by passing arguments. Be
careful if setting a large depth and allowing it to go offsite, you could end
up drifting on to a lot of other domains. All words of three characters and
over are output to stdout. This length can be increased and the words can be
written to a file rather than screen so the app can be automated.

CeWL also has an associated command line app, FAB (Files Already Bagged)
which uses the same meta data extraction techniques to create author/creator
lists from already downloaded.

Homepage: https://digi.ninja/projects/cewl.php
GitHub: https://github.com/digininja/CeWL

Change Log
==========

Version 5.2
-----------

Loads of changes including:

* Code refactoring by @g0tmi1k
* Internationalisation - should now handle non-ASCII sites much better
* Found more ways to pull words out of JavaScript content and other areas
  that aren't normal HTML
* Lots of little bug fixes

Version 5.1
-----------

Added the GPL-3+ licence to allow inclusion in Debian.

Added a Gemfile to make installing gems easier.

Version 5.0
-----------

Adds proxy support from the command line and the ability to pass in
credentials for both basic and digest authentication.

A few other smaller bug fixes as well.

Version 4.3
-----------

CeWL now sorts the words found by count and optionally (new --count argument)
includes the word count in the output. I've left the words in the case
they are in the pages so "Product" is different to "product" I figure that if
it is being used for password generation then the case may be significant so
let the user strip it if they want to. There are also more improvements to the
stability of the spider in this release.

By default, CeWL sticks to just the site you have specified and will go to a
depth of 2 links, this behaviour can be changed by passing arguments. Be
careful if setting a large depth and allowing it to go offsite, you could end
up drifting on to a lot of other domains. All words of three characters
and over are output to stdout. This length can be increased and the words can
be written to a file rather than screen so the app can be automated.

Version 4.2
-----------

Fixes a pretty major bug that I found while fixing a smaller bug for @yorikv.
The bug was related to a hack I had to put in place because of a problem I was
having with the spider, while I was looking in to it I spotted this line which
is the one that the spider uses to find new links in downloaded pages:

	web_page.scan(/href="(.*?)"/i).flatten.map do |link|

This is fine if all the links look like this:

	<a href="test.php">link</a>

But if the link looks like either of these:

	<a href='test.php'>link</a>
	<a href=test.php>link</a>

the regex will fail so the links will be ignored.

To fix this up I've had to override the function that parses the page to find
all the links, rather than use a regex I've changed it to use Nokogiri which
is designed to parse a page looking for links rather than just running through
it with a custom regex. This brings in a new dependency but I think it is worth
it for the fix to the functionality. I also found another bug where a link like
this:

	<a href='#name'>local</a>

which should be ignored as it just links to an internal name was actually being
translated to '/#name' which may unintentionally mean referencing the index
page. I've fixed this one as well after a lot of debugging to find how best to
do it.

A final addition is to allow a user to specify a depth of 0 which allows CeWL
to spider a single page.

I'm only putting this out as a point release as I'd like to rewrite the
spidering to use a better spider, that will come out as the next major release.

Version 4.0/4.1
---------------

The main change in version 4.0/1 is the upgrade to run with Ruby 1.9.x, this
has been tested on various machines and on BT5 as that is a popular platform
for running it and it appears to run fine. Another minor change is that Up to
version 4 all HTML tags were stripped out before the page was parsed for words,
this meant that text in alt and title tags were missed. I now grab the text
from those tags before stripping the HTML to give those extra few works.

Version 3
---------

Addresses a problem spotted by Josh Wright. The Spider gem doesn't handle
JavaScript redirection URLs, for example an index page containing just the
following:

	<script language="JavaScript">
	self.location.href =
	'http://www.FOO.com/FOO/connect/FOONet/Top+Navigator/Home';
	</script>

wasn't spidered because the redirect wasn't picked up. I now scan through a
page looking for any lines containing location.href= and then add the given
URL to the list of pages to spider.

Version 2
---------

Version 2 of CeWL can also create two new lists, a list of email addresses
found in mailto links and a list of author/creator names collected from meta
data found in documents on the site. It can currently process documents in
Office pre 2007, Office 2007 and PDF formats. This user data can then be used
to create the list of usernames to be used in association with the password
list.

Pronunciation
=============
Seeing as I was asked, CeWL is pronounced "cool".

Installation
============
CeWL needs the rubygems package to be installed along with the following gems:

* mime-types
* mini_exiftool
* rubyzip
* spider

All these gems were available by running "gem install xxx" as root. The
mini_exiftool gem also requires the exiftool application to be installed.

Then just save CeWL to a directory and make it executable.

The project page on my site gives some tips on solving common problems people
have encountered while running CeWL - http://www.digininja.org/projects/cewl.php

Usage
=====
Usage: cewl [OPTION] ... URL
	--help, -h: show help
	--depth x, -d x: depth to spider to, default 2
	--min_word_length, -m: minimum word length, default 3
	--offsite, -o: let the spider visit other sites
	--write, -w file: write the output to the file
	--ua, -u user-agent: user agent to send
	--no-words, -n: don't output the wordlist
	--meta, -a include meta data
	--meta_file file: file for metadata output
	--email, -e include email addresses
	--email_file file: file for email output
	--meta-temp-dir directory: the temporary directory used by exiftool when parsing files, default /tmp
	-v: verbose

	URL: The site to spider.

Ruby Doc
========
CeWL is commented up in Ruby Doc format.

Licence
=======
This project released under the Creative Commons Attribution-Share Alike 2.0
UK: England & Wales

( http://creativecommons.org/licenses/by-sa/2.0/uk/ )


Alternatively, you can use GPL-3+ instead the of the original license.

( http://opensource.org/licenses/GPL-3.0 )
