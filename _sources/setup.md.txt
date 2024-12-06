<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Setup
## Dependencies

This project has the following system level dependencies:

* [Linux](https://kernel.org) >= 5.10
* [Python](https://python.org) (latest and latest - 1)
* [uv](https://docs.astral.sh/uv/) (optional, for development)
* [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html) (optional, part of [wireshark](https://www.wireshark.org/))

Python dependencies are listed in `pyproject.toml`.

## Install

An overview of software repos where `gallia` is available is provided by [repology.org](https://repology.org/project/gallia/versions).

### Docker

Docker images are published via the [Github Container registry](https://github.com/Fraunhofer-AISEC/gallia/pkgs/container/gallia).

### Arch Linux 

``` shell-session
$ paru -S gallia
```

### Debian/Ubuntu

``` shell-session
$ sudo apt install pipx
$ pipx install gallia
```

### NixOS

``` shell-session
$ nix shell nixpgks#gallia
```

For persistance add `gallia` to your `environment.systemPackages`, or when you use `home-manager` to `home.packages`.

### Generic

``` shell-session
$ pipx install gallia
```

### Without Install

The `uvx` tool is provided by `uv`.

``` shell-session
$ uvx gallia
```

## Development

[uv](https://docs.astral.sh/uv/) is used to manage dependencies.

### Clone repository

```shell-session
$ git clone https://github.com/Fraunhofer-AISEC/gallia.git
```

### Environment 

`uv` manages the project environment, including the python version.
All `uv` commands must be invoked within the `gallia` repository.

```shell-session
$ pipx install uv
$ uv sync
```

If you want to use a different Python version from the one defined in `.python-version`, the flags `--python-preference only-system` or `--python` for `uv sync` might be helpful; e.g. to use your system provided Python 3.11:

```shell-session
$ uv sync --python-preference only-system --python 3.11
```

#### shell

Enable the venv under `.venv` manually by sourcing:

``` shell-session
$ source .venv/bin/activate
$ source .venv/bin/activate.fish
```

#### run

Run a single command inside the venv without changing the shell environment:

```shell-session
$ uv run gallia
```

## Development with Plugins

If you want to develop gallia and plugins at the same time, then you need to add `gallia` as a dependency to your plugin package.

### Shell Completion
#### bash

```shell-session
# register-python-argcomplete gallia > /etc/bash_completion.d/gallia
```

#### fish

```shell-session
$ mkdir -p ~/.config/fish/completions
$ register-python-argcomplete --shell fish gallia > ~/.config/fish/completions/gallia.fish
```

### IDE Integration

Just use [LSP](https://microsoft.github.io/language-server-protocol/).
Most editors (e.g. [neovim](https://neovim.io/)) support the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/).
The required tools are listed as development dependencies in `pyproject.toml` and are automatically managed by `uv`.
Please refer to the documentation of your text editor of choice for configuring LSP support.
