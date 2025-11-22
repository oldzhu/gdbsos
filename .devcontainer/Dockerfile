# Derived from src/runtime/.devcontainer/libraries/Dockerfile, but using .NET 8.0 jammy base
# See image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.192.0/containers/dotnet/.devcontainer/base.Dockerfile

# [Choice] .NET version: 8.0-jammy
ARG VARIANT=8.0-jammy
FROM mcr.microsoft.com/devcontainers/dotnet:${VARIANT}

# Set up machine requirements to build the repo and the gh CLI
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        cmake \
        llvm \
        llvm-11 \
        llvm-11-tools \
        clang-11 \
        clang \
        build-essential \
        python3 \
        curl \
        git \
        lldb \
        liblldb-dev \
        libunwind8 \
        libunwind8-dev \
        gettext \
        libicu-dev \
        liblttng-ust-dev \
        libssl-dev \
        libkrb5-dev \
        zlib1g-dev \
        ninja-build \
        gdb \
    && rm -rf /var/lib/apt/lists/*
