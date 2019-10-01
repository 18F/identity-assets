run:
	bundle exec jekyll serve

setup:
	bundle check || bundle install

test: build
	bundle exec rspec spec

build:
	bundle exec jekyll build
