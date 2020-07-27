FROM ruby:2.5-alpine

ENV RUBYOPT "rubygems"

COPY Gemfile /usr/src/CeWl/
WORKDIR /usr/src/CeWl

RUN set -ex \
    && apk add  --no-cache --virtual .build-deps build-base \
    && gem install bundler \
    && bundle install \
    && apk del .build-deps

COPY . /usr/src/CeWL

WORKDIR /host
ENTRYPOINT ["/usr/src/CeWL/cewl.rb"]
