#!/bin/sh

cd $(dirname $0)/../..

rsync --checksum --itemize-changes \
      testing/web/lsw*.{js,css} \
      testing/web/summary*.{html,js,css} \
      /var/www/html/results/testing/
