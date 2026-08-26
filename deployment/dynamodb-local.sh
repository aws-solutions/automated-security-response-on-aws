#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Manages a DynamoDB Local instance for tests.
#
# Usage:
#   source dynamodb-local.sh   (to get access to start/stop functions)
#   ddb_local_start             — starts DynamoDB Local (or detects an existing one)
#   ddb_local_stop              — stops it if we started it
#
#   Or as a wrapper for a command:
#   ./dynamodb-local.sh <command...>
#   e.g. ./dynamodb-local.sh npm run check

set -eo pipefail

DDB_PID=""

ddb_local_start() {
    echo "------------------------------------------------------------------------------"
    echo "[Setup] Starting DynamoDB Local"
    echo "------------------------------------------------------------------------------"

    # Check if DynamoDB Local is already running via Docker
    if curl -s http://localhost:8000 >/dev/null 2>&1; then
        echo "DynamoDB Local is already running (likely via Docker)"
        DDB_PID=""
        return 0
    fi

    # Fall back to tar-based installation
    if [[ -z "$DDB_LOCAL_HOME" ]]; then
        echo "ERROR: DDB_LOCAL_HOME environment variable is not set and DynamoDB Local is not running via Docker"
        return 1
    fi

    # Verify DynamoDB Local files exist
    if [[ ! -f "$DDB_LOCAL_HOME/DynamoDBLocal.jar" ]]; then
        echo "ERROR: DynamoDBLocal.jar not found at $DDB_LOCAL_HOME/DynamoDBLocal.jar"
        return 1
    fi

    if [[ ! -d "$DDB_LOCAL_HOME/DynamoDBLocal_lib" ]]; then
        echo "ERROR: DynamoDBLocal_lib directory not found at $DDB_LOCAL_HOME/DynamoDBLocal_lib"
        return 1
    fi

    java -Djava.library.path="$DDB_LOCAL_HOME"/DynamoDBLocal_lib -jar "$DDB_LOCAL_HOME"/DynamoDBLocal.jar -sharedDb -inMemory >/dev/null 2>&1 &
    DDB_PID=$!

    # Wait for DynamoDB Local to be ready
    echo "Waiting for DynamoDB Local to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:8000 >/dev/null 2>&1; then
            echo "DynamoDB Local is ready (attempt $i)"
            break
        fi
        if [ $i -eq 30 ]; then
            echo "ERROR: DynamoDB Local failed to become ready after 30 seconds"
            kill $DDB_PID 2>/dev/null || true
            DDB_PID=""
            return 1
        fi
        sleep 1
    done

    if ! kill -0 $DDB_PID 2>/dev/null; then
        echo "ERROR: DynamoDB Local failed to start"
        DDB_PID=""
        return 1
    fi
    echo "DynamoDB Local started successfully (PID: $DDB_PID)"
}

ddb_local_stop() {
    echo "------------------------------------------------------------------------------"
    echo "[Cleanup] Stopping DynamoDB Local"
    echo "------------------------------------------------------------------------------"
    if [[ -n "$DDB_PID" ]]; then
        kill $DDB_PID 2>/dev/null || true
        DDB_PID=""
    else
        echo "DynamoDB Local was not started by this script (skipping)"
    fi
}

# When executed directly (not sourced), act as a wrapper:
# start DDB, run the provided command, stop DDB, and exit with the command's exit code.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then
        echo "Usage: $0 <command...>"
        echo "  Starts DynamoDB Local, runs the command, then stops DynamoDB Local."
        exit 1
    fi

    ddb_local_start
    trap 'ddb_local_stop' EXIT

    "$@"
fi
