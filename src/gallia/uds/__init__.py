import logging

from gallia.penlog import Logger


logger = Logger("uds.lib", flush=True)
# The asyncio lib logs errors in some conditions to stdout, in addition to
# throwing an exception.  This messes up with our penlog logging.
asyncio_log = logging.getLogger("asyncio")
asyncio_log.setLevel(logging.CRITICAL)
