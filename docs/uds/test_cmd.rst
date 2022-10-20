.. testsetup:: *

   from gallia.cli import create_arg_parser
   config, config_path, parsers = create_arg_parser()
   parser = parsers["parser"]

.. testcode::

   cmd = ['script', 'vecu', 'tcp-lines://127.0.0.1:20162', 'rng']
   args = parser.parse_args(cmd)

.. doctest::

   >>> cmd = ['--elp']
   >>> args = parser.parse_args(cmd)
