# Primitives

Primitives are simple functions to perform singular tasks.

## DTC

This primitive provides functionalities to interact with the ECU's Diagnostic Trouble Codes (DTCs).

### Operations

This primitive supports various operations on DTCs:

* **Reading DTCs**: Retrieves DTC information from the ECU using the `ReadDTCInformation` service.

* **Clearing DTCs**: Clears DTCs from the ECU's memory employing the `ClearDiagnosticInformation` service.

* **Controlling DTC Setting**: Enables or disables setting of new DTCs through the `ControlDTCSetting` service.

### Example Usage:

1. Read all DTCs and show a legend and summaries:
`gallia primitive uds dtc --target <TARGET_URI> --show-legend --show-failed --show-uncompleted read`

2. Clear all DTCs:
`gallia primitive uds dtc --target <TARGET_URI> clear`

3. Stop setting of new DTCs:
`gallia primitive uds dtc --target <TARGET_URI> control --stop`

## ECU Reset

This primitive provides functionalities to reset the ECU using the `0x11` UDS service.

This class offers a way to reset the ECU through the UDS 0x11 service.

### Key functionalities:

1. Switches to the requested diagnostic session using `ecu.set_session` (defaults to `0x01`).
2. Sends the ECU Reset request with the provided subfunction using `ecu.ecu_reset` (defaults to `0x01`).
3. Analyzes the ECU's response to determine the success or failure of the reset operation.

* Logs informative messages throughout the process, including session changes, request attempts, and response outcomes.
    - If successful, logs a message indicating success.
    - If a negative response is received, logs an error message.
    - In case of timeout or connection errors, logs the error and waits before returning.

### Example Usage:

Reset the ECU in session 0x02 utilizing reset level (subfunction) 0x01
`gallia primitive uds ecu-reset --target "isotp://vcan0?is_fd=false&is_extended=false&src_addr=0x701&dst_addr=0x700" --session 0x02 -f 0x01`

This command initiates first switches to the target session (`10 02`) and sends a reset request of the desired level (`11 01`).

### Output:

The class logs informative messages to the console, including:

* Established session with the ECU (if successful).
* Attempted ECU Reset with the provided sub-function.
* Success or failure outcome of the ECU Reset operation.
* Timeout errors in case of communication delays.
* Connection errors if communication with the ECU is lost.