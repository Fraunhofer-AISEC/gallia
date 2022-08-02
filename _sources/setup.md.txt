<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Setup
## Dependencies

This project has the following system level dependencies:

* [Linux](https://kernel.org) >= 5.10
* [Python](https://python.org) >= 3.9
* [poetry](https://python-poetry.org) (optional, for development)
* [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html) (optional, part of [wireshark](https://www.wireshark.org/))

Python dependencies are listed in `pyproject.toml`

## Install
### Arch Linux 

``` shell-session
$ paru -S gallia
```

### Manual

``` shell-session
$ pip install gallia
```

## Development

The [poetry build system](https://python-poetry.org/) is used to manage dependencies.

### Clone repository

```shell-session
$ git clone https://github.com/Fraunhofer-AISEC/gallia.git
```

### Environment 

Poetry will create a unique [virtual python environment](https://docs.python.org/3/library/venv.html) with all the required dependencies.
All poetry commands must be invoked within the `gallia` repository.

```shell-session
$ poetry install
```

More poetry commands are documented [upstream](https://python-poetry.org/docs/cli/).

#### shell

The created venv can be enabled via poetry with the `shell` command.
A new shell will be spawned with the enabled environment.

```shell-session
$ poetry shell
```

#### run

Run a single command inside the venv without changing the shell environment:

```shell-session
$ poetry run gallia
```

## Development with Plugins

If you want to develop gallia and plugins at the same time, then you need to manage your `gallia` (e.g. in `~/.venvs/gallia`) virtual python environment by yourself.
You can use `poetry install` to install multiple plugin repos into the `gallia` venv.

``` shell-session
$ python -m venv ~/.venvs/gallia
$ source ~/.venvs/gallia/activate
$ cd /path/to/gallia && poetry install
$ cd /path/to/gallia-plugins && poetry install
```

If it does not work, you might try deleting the venvs managed by `poetry` via:

``` shell-session
$ rm -rf ~/.cache/pypoetry/virtualenvs/*
```

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
#### Pycharm

`pycharm` offers [native support](https://www.jetbrains.com/help/pycharm/poetry.html) for the `poetry` build system.
The `src` folder in the gallia repository needs to be configured as `Sources Root` in pycharm.

#### LSP

Most editors (e.g. [neovim](https://neovim.io/)) support the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/).
The required tools are listed as development dependencies in `pyproject.toml` and are installed automatically via poetry.
Please refer to the documentation of your text editor of choice for configuring LSP support.
