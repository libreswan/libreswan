#!/bin/bash

dExe() {
  local user=$1
  local name=$2
  local cmd=$3

  docker exec -u "$user" "$name" /bin/bash -c "$cmd"
}

dRun() {
  local name=$1
  local img=$2
  local cmd=$3

  local user=$(id -un)
  local gid=$(id -g)
  local group=$(id -gn)

  docker rm -f "$name" || true
  docker run --privileged -d -v /tmp:/tmp -v "/home/$user:/home/$user" -h "$name" --name "$name" "$img" init
  dExe "root" "$name" "groupadd -g $gid $group && useradd -M -s /bin/bash -g $gid -u $UID $user"
  dExe "$UID" "$name" "$cmd"
}

set -eu

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR/.."

for doc in $(testing/dockerfiles/docker.sh list); do
  name=$(printf "$doc" | sed "s#curtine/##" | sed "s/:/-/")
  dRun "$name" "$doc" "cd $PWD && \
                       export CC=gcc && \
                       make clean && \
                       make -j3 all"
done

