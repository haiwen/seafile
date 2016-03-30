#!/bin/bash
THISDIR="$(cd "$(dirname "$0")" && pwd)"
CONTAINER=ubuntu:14.04

echo "Pulling last version of container $CONTAINER"
(set -x ; docker pull "$CONTAINER")

echo "Executing run_integration_tests.sh inside the $CONTAINER container."
(set -x ; docker run -v "$THISDIR":/opt/seafile/seafile -t "$CONTAINER" /opt/seafile/seafile/run_integration_tests.sh)
