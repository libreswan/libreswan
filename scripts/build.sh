#!/bin/bash

set -eu

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$dir/.."

if [ "$(uname)" != "Linux" ]; then
  make -j3 all
  make -j3 install
  exit 0
fi

dockerfiles/docker.sh pull

for doc in $(dockerfiles/docker.sh list); do
  git clean -fdx
  name=$(printf $doc | sed "s#curtine/##" | sed "s/:/-/")
  docker run -v "$PWD":"$PWD" -h "$name" --name "$name" "$doc" \
             /bin/bash -c "cd $PWD && \
                           export CC=$CC && \
                           make -j3 all && \
                           make -j3 install"
done

