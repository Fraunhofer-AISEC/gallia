### Define Model
```python title="commands.py"
--8<-- "examples/commands.py"
```

### Check Help
```console
$ python3 examples/commands.py --help
usage: Example Program [-h] [-v] [--verbose] {build,serve} ...

Example Description

commands:
  {build,serve}
    build        build command
    serve        serve command

optional arguments:
  --verbose      verbose flag (default: False)

help:
  -h, --help     show this help message and exit
  -v, --version  show program's version number and exit

Example Epilog
```

### Check Commands Help
```console
$ python3 examples/commands.py build --help
usage: Example Program build [-h] --location LOCATION

required arguments:
  --location LOCATION  build location

help:
  -h, --help           show this help message and exit
```
```console
$ python3 examples/commands.py serve --help
usage: Example Program serve [-h] --address ADDRESS --port PORT

required arguments:
  --address ADDRESS  serve address
  --port PORT        serve port

help:
  -h, --help         show this help message and exit
```

### Parse Arguments
```console
$ python3 examples/commands.py --verbose serve --address 127.0.0.1 --port 8080
verbose=True build=None serve=ServeCommand(address=IPv4Address('127.0.0.1'), port=8080)
```
