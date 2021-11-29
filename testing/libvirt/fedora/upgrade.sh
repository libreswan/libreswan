#!/bin/sh

set -xe

exec dnf upgrade -y "$@"
