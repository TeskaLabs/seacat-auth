#!/bin/sh

#!/bin/sh

# Detect docker or podman
if (docker version 2> /dev/null 1> /dev/null); then
    DOCKER=docker
elif (podman version 2> /dev/null 1> /dev/null> /dev/null); then
    DOCKER=podman
else
    echo "Neither Docker nor Podman could be found. Please install one of them."
    exit 1
fi

$DOCKER build -t mkdocs-material .
exec $DOCKER run --rm -p 8000:8000 -v ${PWD}:/docs mkdocs-material
