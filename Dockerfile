FROM ruby:2.5

WORKDIR /usr/src/app

RUN git clone https://github.com/digininja/CeWL/ 

WORKDIR /usr/src/app/CeWL

RUN gem install bundler

RUN bundle install

RUN gem source -c

RUN gem install --user-install spider http_configuration mini_exiftool zip mime-types



RUN RUBYOPT="rubygems"

ENTRYPOINT ["/usr/src/app/CeWL/cewl.rb"]