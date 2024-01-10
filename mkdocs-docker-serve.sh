#!/bin/sh

exec docker run --rm -p 8000:8000 -v ${PWD}:/docs squidfunk/mkdocs-material
