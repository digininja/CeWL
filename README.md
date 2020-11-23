# CeWL - Custom Word List generator

Copyright(c) 2020, Robin Wood <robin@digi.ninja>

Based on a discussion on PaulDotCom (episode 129) about creating custom word lists spidering a targets website and collecting unique words I decided to write CeWL, the Custom Word List generator. CeWL is a ruby app which spiders a given URL to a specified depth, optionally following external links, and returns a list of words which can then be used for password crackers such as John the Ripper.

By default, CeWL sticks to just the site you have specified and will go to a depth of 2 links, this behaviour can be changed by passing arguments. Be careful if setting a large depth and allowing it to go offsite, you could end up drifting on to a lot of other domains. All words of three characters and over are output to stdout. This length can be increased and the words can be written to a file rather than screen so the app can be automated.

CeWL also has an associated command line app, FAB (Files Already Bagged) which uses the same meta data extraction techniques to create author/creator lists from already downloaded.

For anyone running CeWL with Ruby 2.7, you might get some warnings in the style:

```
.../ruby-2.7.0/gems/mime-types-3.2.2/lib/mime/types/logger.rb:30: warning: `_1' is reserved for numbered parameter; consider another name
```
This is due to a new feature introduced in 2.7 which conflices with one line of code in the logger script from the mime-types gem. There is an update for it in the [gem's repo](https://github.com/mime-types/ruby-mime-types/commit/c44673179d24e495e5fb93282a87d37f09925d25#diff-f0a644249326afd54e7a0b90c807f8a6) so hopefully that will be released soon. Till then, as far as I can tell, the warning does not affect CeWL in any way. If, for asthetics, you want to hide the warning, you can run the script as follows:

```
ruby -W0 ./cewl.rb
```

Homepage: <https://digi.ninja/projects/cewl.php>

GitHub: <https://github.com/digininja/CeWL>

## Change Log

### Version 5.5.0

* Grouping words together.

### Version 5.4.9

* Added Docker support.

### Version 5.4.8

* Updated the parser so that it looks at the content on all pages which are returned, not just those with a 200 return code.

### Version 5.4.7

* Added the `--allowed parameter` to limit crawling to URLs matching the passed RegEx. Work done by [5p1n](https://github.com/5p1n/).

### Version 5.4.6

* Added the `--lowercase` parameter to convert all letters to lower case.
* Added the `--convert-umlauts` parameter to convert Latin-1 umlauts (e.g. "ä" to "ae", "ö" to "oe", etc.).

### Version 5.4.3

* Added the `--with-number` parameter to make words include letters and numbers.

### Version 5.4.2

* Merged an update to change the way usage instructions are shown.
* Updated instructions on installing gems.
* Updated README.

### Version 5.4.1

* A line to add a / to the end of the URL had been commented out. I don't remember why it was done but I'm putting it back in. See [issue 26](https://github.com/digininja/CeWL/issues/26).

### Version 5.4

* Steven van der Baan added the ability to hit ctrl-c and keep the results so far.

### Version 5.3.1

* Added the ability to handle non-standard port numbers.
* Added lots more debugging and a new --debug parameter.

### Version 5.3

* Added the command line argument --header (-H) to allow headers to be passed in.
* Parameters are specified in name:value pairs and you can pass multiple.

### Version 5.2

Loads of changes including:

* Code refactoring by [@g0tmi1k](https://github.com/g0tmi1k)
* Internationalisation - should now handle non-ASCII sites much better
* Found more ways to pull words out of JavaScript content and other areas that aren't normal HTML
* Lots of little bug fixes

### Version 5.1

* Added the GPL-3+ licence to allow inclusion in Debian.
* Added a Gemfile to make installing gems easier.

### Version 5.0

* Adds proxy support from the command line and the ability to pass in credentials for both basic and digest authentication.
* A few other smaller bug fixes as well.

### Version 4.3

CeWL now sorts the words found by count and optionally (new --count argument) includes the word count in the output. I've left the words in the case they are in the pages so "Product" is different to "product" I figure that if it is being used for password generation then the case may be significant so let the user strip it if they want to. There are also more improvements to the stability of the spider in this release.

By default, CeWL sticks to just the site you have specified and will go to a depth of 2 links, this behaviour can be changed by passing arguments. Be careful if setting a large depth and allowing it to go offsite, you could end up drifting on to a lot of other domains. All words of three characters and over are output to stdout. This length can be increased and the words can be written to a file rather than screen so the app can be automated.

### Version 4.2

Fixes a pretty major bug that I found while fixing a smaller bug for @yorikv. The bug was related to a hack I had to put in place because of a problem I was having with the spider, while I was looking in to it I spotted this line which is the one that the spider uses to find new links in downloaded pages:

```
web_page.scan(/href="(.*?)"/i).flatten.map do |link|
```

This is fine if all the links look like this:

```
<a href="test.php">link</a>
```

But if the link looks like either of these:

```
<a href='test.php'>link</a>
<a href=test.php>link</a>
```

The regex will fail so the links will be ignored.

To fix this up I've had to override the function that parses the page to find all the links, rather than use a regex I've changed it to use Nokogiri which is designed to parse a page looking for links rather than just running through it with a custom regex. This brings in a new dependency but I think it is worth it for the fix to the functionality. I also found another bug where a link like this:

```
<a href='#name'>local</a>
```

Which should be ignored as it just links to an internal name was actually being translated to '/#name' which may unintentionally mean referencing the index page. I've fixed this one as well after a lot of debugging to find how best to do it.

A final addition is to allow a user to specify a depth of 0 which allows CeWL to spider a single page.

I'm only putting this out as a point release as I'd like to rewrite the spidering to use a better spider, that will come out as the next major release.

### Version 4.0/4.1

The main change in version 4.0/1 is the upgrade to run with Ruby 1.9.x, this has been tested on various machines and on BT5 as that is a popular platform for running it and it appears to run fine. Another minor change is that Up to version 4 all HTML tags were stripped out before the page was parsed for words, this meant that text in alt and title tags were missed. I now grab the text from those tags before stripping the HTML to give those extra few works.

### Version 3

Addresses a problem spotted by Josh Wright. The Spider gem doesn't handle JavaScript redirection URLs, for example an index page containing just the following:

```
<script language="JavaScript">
self.location.href =
'http://www.FOO.com/FOO/connect/FOONet/Top+Navigator/Home';
</script>
```

Wasn't spidered because the redirect wasn't picked up. I now scan through a page looking for any lines containing location.href= and then add the given URL to the list of pages to spider.

### Version 2

Version 2 of CeWL can also create two new lists, a list of email addresses
found in mailto links and a list of author/creator names collected from meta
data found in documents on the site. It can currently process documents in
Office pre 2007, Office 2007 and PDF formats. This user data can then be used
to create the list of usernames to be used in association with the password
list.

## Pronunciation

Seeing as I was asked, CeWL is pronounced "cool".

## Installation

CeWL needs the rubygems package to be installed along with the following gems:

* mime
* mime-types
* mini_exiftool
* nokogiri
* rubyzip
* spider

All these gems were available by running "gem install xxx" as root. The
mini_exiftool gem also requires the exiftool application to be installed.

Then just save CeWL to a directory and make it executable.

The project page on my site gives some tips on solving common problems people
have encountered while running CeWL - https://digi.ninja/projects/cewl.php

## Usage

```
./cewl.rb

CeWL 5.4.2 (Break Out) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
Usage: cewl [OPTIONS] ... <url>

    OPTIONS:
	-h, --help: Show help.
	-k, --keep: Keep the downloaded file.
	-d <x>,--depth <x>: Depth to spider to, default 2.
	-m, --min_word_length: Minimum word length, default 3.
	-o, --offsite: Let the spider visit other sites.
	-w, --write: Write the output to the file.
	-u, --ua <agent>: User agent to send.
	-n, --no-words: Don't output the wordlist.
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
```

### Running CeWL in a Docker container

To quickly use CeWL on your machine with Docker, you have to build it :
1. Build the container :
    ```sh
    docker build -t cewl .
    ```
2. Container usage without interacting with local files :
    ```sh
    docker run -it --rm cewl [OPTIONS] ... <url>
    ```
3. Container usage with local files as input or output :
    ```sh
    # you have to mount the current directory when calling the container 
    docker run -it --rm -v "${PWD}:/host" cewl [OPTIONS] ... <url>
    ```

I am going to stress here, I am not going to be offering any support for this. The work was done by [@loris-intergalactique](https://github.com/loris-intergalactique) who has offered to field any questions on it and give support. I don't use or know Docker, so please, don't ask me for help.

## Licence

This project released under the Creative Commons Attribution-Share Alike 2.0 UK: England & Wales

<http://creativecommons.org/licenses/by-sa/2.0/uk/>

Alternatively, you can use GPL-3+ instead the of the original license.

<http://opensource.org/licenses/GPL-3.0>
