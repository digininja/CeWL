# CeWL - Custom Word List generator

Copyright(c) 2022, Robin Wood <robin@digi.ninja>

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

## Pronunciation

Seeing as I was asked, CeWL is pronounced "cool".

## Installation

CeWL needs the following gems to be installed:

* mime
* mime-types
* mini_exiftool
* nokogiri
* rubyzip
* spider

The easiest way to install these gems is with Bundler:

```
gem install bundler
bundle install
```

Alternatively, you can install them manually with:

```
gem install xxx
```

The gem `mini_exiftool` gem also requires the exiftool application to be installed.

Assuming you cloned the GitHub repo, the script should by executable by default, but if not, you can make it executable with:

```
chmod u+x ./cewl.rb
```

The project page on my site gives some tips on solving common problems people
have encountered while running CeWL - https://digi.ninja/projects/cewl.php

## Usage

```
./cewl.rb

CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
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
