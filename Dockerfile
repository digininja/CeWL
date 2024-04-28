FROM ruby:3-alpine

ENV RUBYOPT "rrubygems"

COPY Gemfile /usr/src/CeWL/
WORKDIR /usr/src/CeWL

RUN apk add gcompat
RUN set -ex \
    && apk add  --no-cache --virtual .build-deps build-base \
    && gem install bundler \
    && bundle install \
    && apk del .build-deps

COPY . /usr/src/CeWL

WORKDIR /host
ENTRYPOINT ["/usr/src/CeWL/cewl.rb"]
