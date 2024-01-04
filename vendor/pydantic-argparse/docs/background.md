## Overview
Before delving into the documentation, examples and code reference, it is first
necessary to explore and understand why you may want to use this package.

## Tenets
The design goals of `pydantic-argparse` are summarised by these core tenets.

#### Simple
:  `pydantic-argparse` has a simple API and code-base.

#### Opinionated
:  `pydantic-argparse` is deliberately limited with *one way* of doing things.

#### Typed
:  `pydantic-argparse` fully supports type-hinting and `mypy`.

## Rationale
There are many benefits to using `pydantic-argparse` over a more traditional
argument parsing package that uses a functional api. Some of the most valuable
benefits are outlined below.

#### Declarative Arguments
!!! success ""
    Arguments are defined declaratively using `pydantic` models. This means the
    command-line interface for your application has a strict schema, that is
    easy to view, modify or even export to other formats such as `JSON Schema`.

#### Familiar Syntax
!!! success ""
    Due to the use of `pydantic` models and standard type-hinting, there is
    almost no new syntax or API to learn. Just declare your interface with a
    *dataclass-like* `pydantic` model, and let `pydantic-argparse` parse your
    arguments.

#### Type Hints
!!! success ""
    Due to the use of `pydantic` models, your parsed command-line arguments are
    just an instance of a type-hinted class. This means that your arguments can
    support auto-completion, linting, mypy and other tools in your IDE.

#### Pydantic Validation
!!! success ""
    Due to the use of `pydantic` models, your command-line interface is able to
    heavily leverage `pydantic`'s validation system to provide a *very* large
    number of different types.

#### Confidence
!!! success ""
    As a result of type-hinting and `pydantic` validation, you can have the
    confidence that once your command-line arguments have been parsed, their
    type and validity have been confirmed - you don't have to check or worry
    about them again.

## Drawbacks
There are also some drawbacks to using `pydantic-argparse`, depending on the
size of your project, the features you require and the programming paradigms
that you agree with. Some of the possible drawbacks are outlined below.

#### Extra Dependencies
!!! warning ""
    While `pydantic-argparse` itself depends *only* on `pydantic`, it has a
    number of transient dependencies due to the dependencies of `pydantic`
    itself. If your application is small, it may not be suitable to pull in
    `pydantic` and its dependencies for a simple command-line interface.

#### Opinionated Design
!!! warning ""
    `pydantic-argparse` is a very opinionated package by design. It aims for a
    simple API, and to be both full featured while limiting excessive choices.
    For example, there are no *positional* arguments in `pydantic-argparse`;
    only *optional* and *required* arguments. If your opinions do not align
    with these design choices, then you may not want to use the package.

#### Nested Models
!!! warning ""
    Sub-commands are supported by *nesting* `pydantic` models. This means that
    for each sub-command, an additional model must be defined. If your
    application requires many different sub-commands, it may result in a large
    number of `pydantic` models.

## Alternatives
There are many alternative argument parsing packages that already exist for
Python. Some of the most popular are outlined below.

#### [Argparse][1]
> `argparse` is a standard-library module that makes it easy to write
> user-friendly command-line interfaces. The program defines what arguments it
> requires, and `argparse` will figure out how to parse those out of
> `sys.argv`. The `argparse` module also automatically generates help and usage
> messages and issues errors when users give the program invalid arguments.

#### [Click][2]
> `click` is a Python package for creating beautiful command line interfaces in
> a composable way with as little code as necessary. It’s the “Command Line
> Interface Creation Kit”. It’s highly configurable but comes with sensible
> defaults out of the box.

#### [Typer][3]
> `typer` is a library for building CLI applications that users will love using
> and developers will love creating. Based on Python 3.6+ type hints. The key
> features are that it is intuitive to write, easy to use, short and starts
> simple but can grow large. It aims to be the `fastapi` of command-line
> interfaces.

## Comparison
A feature comparison matrix of the alternatives outlined above is shown below.

|                                 | `argparse`         | `click`            | `typer`            | `pydantic-argparse` |
| ------------------------------: | :----------------: | :----------------: | :----------------: | :-----------------: |
| **Arguments**                                                                                                        |
| *Optional Arguments*            | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:  |
| *Required Arguments*            | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:  |
| *Positional Arguments*          | :white_check_mark: | :white_check_mark: | :white_check_mark: |                     |
| *Sub-Commands*                  | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:  |
| **Argument Types**                                                                                                   |
| *Regular Arguments*             | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:  |
| *Variadic Arguments*            | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:  |
| *Flag Arguments*                | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:  |
| *Choice Arguments*              | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:  |
| **Validation**                                                                                                       |
| *Type Validation*               | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:  |
| *Automatic Validation*          |                    |                    | :white_check_mark: | :white_check_mark:  |
| *Pydantic Validation*           |                    |                    |                    | :white_check_mark:  |
| **Design Pattern**                                                                                                   |
| *Functional Definition*         | :white_check_mark: | :white_check_mark: | :white_check_mark: |                     |
| *Declarative Definition*        |                    |                    |                    | :white_check_mark:  |
| *Function Decorators*           |                    | :white_check_mark: | :white_check_mark: |                     |
| *Function Signature Inspection* |                    |                    | :white_check_mark: |                     |
| **Extra Features**                                                                                                   |
| *Typing Hinting*                |                    | :white_check_mark: | :white_check_mark: | :white_check_mark:  |
| *Shell Completion*              |                    | :white_check_mark: | :white_check_mark: |                     |
| *Environment Variables*         | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark:  |

<!--- Reference -->
[1]: https://docs.python.org/3/library/argparse.html
[2]: https://click.palletsprojects.com/
[3]: https://typer.tiangolo.com/
