# Setup

## Dependencies

This project has the following system level dependencies:

* Linux >= 5.10
* Python 3.9
* poetry

Python dependencies are listed in `pyproject.toml`

## Install

###  1) Clone repository

```shell-session
$ cd /install/path
$ git clone https://github.com/Fraunhofer-AISEC/gallia.git
$ cd gallia
```

### 2) Install utils

**penlog**

See https://github.com/Fraunhofer-AISEC/penlog

```shell-session
$ make
```

**penrun**

Install `bin/penrun` into `$PATH`.
[`$HOME/.local/bin`](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html) might be a good candidate.

### 3) Install gallia

Poetry will create a unique venv with all the required dependencies:

```shell-session
$ poetry install
```

### 4) Enable Shell Completion

**bash**

```shell-session
# register-python-argcomplete gallia > /etc/bash_completion.d/gallia
# echo "complete -F _command penrun" > /etc/bash_completion.d/penrun
```

**fish**

```shell-session
$ test ! -d ~/.config/fish/completions && mkdir -p ~/.config/fish/completions
$ register-python-argcomplete --shell fish gallia > ~/.config/fish/completions/gallia.fish
$ cp misc/penrun.fish ~/.config/fish/completions
```

## Development
We use the poetry build system to manage dependencies and to install the gallia package.
This section lists some useful commands to get started with poetry.

**shell**

You can enter the venv created by poetry with the `shell` command:

```shell-session
$ poetry shell
```

**run**

To run a single command inside the venv, use the `run` command:

```shell-session
$ poetry run gallia
```

**build**

You can create python whl files with the `build` command:

```shell-session
$ poetry build
```

**pip**

You can also install gallia with pip:

```shell-session
$ python -m venv venv
$ . venv/bin/activate.sh
$ pip install .
```

**IDE integration**

`pycharm` offers [native support](https://www.jetbrains.com/help/pycharm/poetry.html) for the `poetry` build system.
You need to mark the `src` folder of the project as `Sources Root`,
otherwise `pycharm` does not find the `gallia` package.

For any IDE, which has no direct support for `poetry`, 
you can use the `pip` approach to install `gallia` to a regular `venv`.
