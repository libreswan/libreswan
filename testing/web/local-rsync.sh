#!/bin/sh

cd $(dirname $0)/../..

rsync --archive --itemize-changes \
      --delete \
      --prune-empty-dirs \
      --include '*/' \
      --include '*.diff' \
      --include '*.html' \
      --include '*.json' \
      --include '*.js' \
      --include '*.css' \
      --exclude '*/*' \
      testing.libreswan.org:results \
      /var/www/html/
