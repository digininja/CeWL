FROM ruby:3-alpine

LABEL org.opencontainers.image.description A docker image to help users run CeWL without having to install all the Ruby dependencies.

ENV RUBYOPT="rrubygems"

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
