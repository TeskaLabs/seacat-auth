#!/bin/sh

exec docker run --rm -p 8003:8000 -v ${PWD}:/docs squidfunk/mkdocs-material

