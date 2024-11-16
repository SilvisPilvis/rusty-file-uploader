#!/bin/env bash

# Check if exactly one argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 [prod|build|dev|api]"
    exit 1
fi

# Handle prod case
if [ "$1" = "prod" ]; then
    cargo run --release
    if [ $? -ne 0 ]; then
        echo "Failed to run the server"
        exit 1
    fi
fi

# Handle build case
if [ "$1" = "build" ]; then
    cargo build --release
    if [ $? -ne 0 ]; then
        echo "Failed to build"
        exit 1
    fi
fi

# Handle dev case
if [ "$1" = "dev" ]; then
    cargo run
    if [ $? -ne 0 ]; then
        echo "Failed to run dev server"
        exit 1
    fi
fi

# Handle api case
if [ "$1" = "api" ]; then
    ./target/release/rusty-file-upload
   if [ $? -ne 0 ]; then
       echo "Failed to run API server"
       exit 1
   fi
fi
