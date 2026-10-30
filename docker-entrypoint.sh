#!/bin/sh
# Started as root (the image's default USER, implicitly): needed to chown
# ./reports and ./db, which docker-compose.yml bind-mounts from the host -
# a bind mount replaces whatever ownership the image set at build time, so
# this has to happen at container start, not build time. gosu then drops
# to the unprivileged "app" user before exec'ing the real process; no
# application code ever runs as root (docs/HISTORY.md, section 27).
set -e

chown -R app:app /app/reports /app/db

exec gosu app "$@"
