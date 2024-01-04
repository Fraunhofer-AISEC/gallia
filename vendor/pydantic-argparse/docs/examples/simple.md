### Define Model
```python title="simple.py"
--8<-- "examples/simple.py"
```

### Check Help
```console
$ python3 simple.py --help
usage: Example Program [-h] [-v] --string STRING --integer INTEGER --flag |
                       --no-flag [--second-flag] [--no-third-flag]

Example Description

required arguments:
  --string STRING    a required string
  --integer INTEGER  a required integer
  --flag, --no-flag  a required flag

optional arguments:
  --second-flag      an optional flag (default: False)
  --no-third-flag    an optional flag (default: True)

help:
  -h, --help         show this help message and exit
  -v, --version      show program's version number and exit

Example Epilog
```

### Parse Arguments
```console
$ python3 simple.py --string hello --integer 42 --flag
string='hello' integer=42 flag=True second_flag=False third_flag=True
```
