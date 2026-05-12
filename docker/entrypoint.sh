#!/bin/sh
# Container entrypoint for paddock-server.
#
# Persistent volumes mounted by Railway / Fly / generic Docker hosts
# typically come up owned by root, which prevents the unprivileged
# `paddock` user (UID 10001) from writing the WAL and SSTables under
# $DATA_DIR. We `chown` once per container start and then drop
# privileges via `gosu` before exec'ing the server, so the long-lived
# process never runs as root.
set -eu

: "${DATA_DIR:=/data}"

chown -R paddock:paddock "$DATA_DIR"
exec gosu paddock:paddock "$@"
