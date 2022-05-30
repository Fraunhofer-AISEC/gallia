# Setup
## Dependencies

This project has the following system level dependencies:

* [Linux](https://kernel.org) >= 5.10
* [Python](https://python.org) >= 3.9
* [poetry](https://python-poetry.org) (optional, for development)
* [dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html) (optional, part of [wireshark](https://www.wireshark.org/))
* [jq](https://stedolan.github.io/jq/) (optional, required for `penrun`)
* [penlog](https://github.com/Fraunhofer-AISEC/penlog) ([hr](https://fraunhofer-aisec.github.io/penlog/hr.1.html) optional for reading logfiles)

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

#### penrun (optional)

Install `bin/penrun` into `$PATH`.
[`$HOME/.local/bin`](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html) might be a good candidate.

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

#### pip

Poetry and the [`pyproject.toml` approach](https://pip.pypa.io/en/stable/reference/build-system/pyproject-toml/) is compatible to the classic `pip` way.
Caveat: Version pinning is ignored py this approach.

```shell-session
$ python -m venv venv
$ . venv/bin/activate.sh
$ pip install .
```

### Shell Completion
#### bash

```shell-session
# register-python-argcomplete gallia > /etc/bash_completion.d/gallia
# echo "complete -F _command penrun" > /etc/bash_completion.d/penrun
```

#### fish

```shell-session
$ test ! -d ~/.config/fish/completions && mkdir -p ~/.config/fish/completions
$ register-python-argcomplete --shell fish gallia > ~/.config/fish/completions/gallia.fish
$ cp misc/penrun.fish ~/.config/fish/completions
```

### IDE Integration
#### Pycharm

`pycharm` offers [native support](https://www.jetbrains.com/help/pycharm/poetry.html) for the `poetry` build system.
The `src` folder in the gallia repository needs to be configured as `Sources Root` in pycharm.

#### LSP

Most editors (e.g. [neovim](https://neovim.io/)) support the [Language Server Protocol](https://microsoft.github.io/language-server-protocol/).
The required tools are listed as development dependencies in `pyproject.toml` and are installed automatically via poetry.
Please refer to the documentation of your text editor of choice for configuring LSP support.
