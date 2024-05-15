<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Scan Modes

A UDS scan usually covers multiple phases:

1. Searching for ECUs on the relevant transport: **Discovery Scan**
2. Searching for UDS sessions on the found ECUs: **Session Scan**
3. Searching for UDS services on the found ECUs: **Service Scan**
4. Searching for UDS identifiers in discovered UDS services: **Identifier Scan**
5. Additional service specific scans, such as **Memory Scan**, **Fuzzing**, …

## Discovery Scan

Discovery scans are specific for the underlying transport, such as DoIP or ISO-TP.
The idea is crafting a valid UDS payload which is valid and at least some answer is expected.
A well working payload is `1001` which is a request to the DiagnosticSessionControl service.
This request instructs an ECU to change to the so called DefaultSession.
The DiagnosticSessionControl service and the DefaultSession should be always available, thus this payload is a good candidate for a discovery scan.
Payloads different from `1001` can be used as well; for instance `1003` to enable the ExtendedDiagnosticSession (session id `0x03`).
Another well working example is `3E00`, the TesterPresent service.

The **addressing** of the ECU is provided by the underlying transport protocol.
Most of the time there are two addresses: the tester address and the ECU address.
The basic idea of a discovery scan is sending a valid UDS payload to all valid ECU addresses with a fixed tester address.
When a valid answer is received an ECU has been found.

### DoIP

The [Diagnostics Over Internet Protocol (DoIP)](https://www.iso.org/standard/74785.html) is a application level protocol on top of TCP enabling tunneling UDS messages.
As an advantage all features of modern operating systems can be used.
Furthermore, no custom hardware, such as expensive CAN bus adapters are required.

```{note}
The user needs to provide a DHCP server enabling the communication stack on the DoIP gateway's side.
```

DoIP has three parameters which are required to establish a communication channel to an ECU:

1. **SourceAddress**: In the automotive chargon also called *tester address*. It is often static and set to `0x0e00`.
2. **TargetAddress**: This is the address of a present ECU. This parameter needs to be discovered.
3. **RoutingActivationType**: DoIP provides further optional layers of authentication which can e.g. be vendor specific. Since `gallia` needs UDS endpoints this is most likely `WWH_OB`, which is a symbolic identifier for the constant `0x01`. Optionally, the RoutingActivationType can be scanned in order to find vendor specific routing methods.

Assuming DHCP and the networking setup is running properly, the DoIP connection establishment looks like the following:

1. TCP connect to the DoIP gateway. The IP address of the gateway is set by the mentioned user controlled DHCP server.
2. Sending a RoutingActivationRequest; the gateway must acknowledge this.
3. UDS requests can be tunneled to arbitrary ECUs using appropriate DoIP `DiagnosticMessage` packets.

The mentioned `DiagnosticMessage` packets contain a `SourceAddress`, a `TargetAddress`, and a `UserData` field.
For the discovery scan on DoIP first step 1. and 2. from the described connection establishment process are performed.
Subsequently, a valid UDS message (c.f. previous section) is the put in the `UserData` field and the  `TargetAddress` field is iterated.
When a valid answer is received an ECU has been found; when the gateway sends a NACK or just timeouts, no ECU is available on the tried `TargetAddress`.

### ISO-TP

#### Functionality Overview

- Scans a specified CAN ID range to locate potential ECU endpoints.
- Sends a user-defined ISO-TP PDU (Protocol Data Unit) to discovered CAN IDs to identify responsive endpoints (`TesterPresent` - `3E 00` by default).
- Analyzes responses to determine if a valid UDS endpoint is present.
- Optionally queries the ECU description by reading a data identifier (DID), `0xF197` by default.

For a discovery scan it is important to distinguish whether the tester is connected to a filtered interface (e.g. the OBD connector) or to an unfiltered interface (e.g. an internal CAN bus).
In order to not confuse the discovery scanner, the so called *idle traffic* needs to be observed.
The idle traffic consists of the mentioned cyclic messages of the can bus.
Since there is no concept of a connection on the CAN bus itself and the parameters for the ISO-TP connection are unknown at the very first stage, an educated guess for a deny list is required.
Typically, `gallia` waits for a few seconds and observes the CAN bus traffic (5 seconds by default).
Subsequently, a deny filter is configured which filters out all CAN IDs seen in the idle traffic.

From a high level perspective, the destination ID is iterated and a valid payload is sent.
If a valid answer is received, an ECU has been found.

#### Detailed Functionality Description

This method performs the following steps:

1. **Connect to CAN Transport:**
    - Establishes a connection to the specified CAN interface using the `RawCANTransport.connect` method.

2. **Record Idle Bus Communication (Optional):**
    - If `args.sniff_time` is greater than zero, the method sniffs the CAN bus for the specified duration to capture any existing communication.
    - The captured CAN addresses are stored in the `addr_idle` variable.
    - The transport filter is then set to exclude these idle addresses using `transport.set_filter(addr_idle, inv_filter=True)`.

3. **Parse UDS Request:**
    - Parses the UDS service PDU (Protocol Data Unit) from the provided `args.pdu` argument using the `UDSRequest.parse_dynamic` method.

4. **Build ISO-TP Frame:**
    - Constructs an ISO-TP frame based on the parsed UDS request.
    - If `args.padding` is provided, the frame is padded with the specified value.
    - The `build_isotp_frame` method is used, potentially incorporating extended addressing if `args.extended_addr` is True.

5. **Iterate Through CAN IDs:**
    - Loops through the CAN ID range specified by `args.start` and `args.stop` (inclusive).
    - A short sleep is introduced between iterations using `asyncio.sleep(args.sleep)`.

6. **Send ISO-TP Frame and Handle Response:**
    - Determines the destination address (DST) for the frame:
        - If extended addressing is enabled (`args.extended_addr`), the tester address (`args.tester_addr`) is used.
        - Otherwise, the current CAN ID from the loop (`ID`) is used.
    - Sends the constructed ISO-TP frame to the determined DST address with a timeout of 0.1 seconds using `transport.sendto`.
    - Attempts to receive a response within a timeout of 0.1 seconds using `transport.recvfrom`.
        - If no response is received within the timeout, the loop continues to the next CAN ID.
        - If the received address (source address) matches the transmitted address (DST), it's considered a self-response and the loop skips to the next CAN ID.

    - Handles received responses:
        - If multiple responses are received for the same CAN ID, it's potentially indicative of a broadcast triggered by the request.
            - The method logs a message and continues iterating.
        - If the response size suggests a large ISO-TP packet, it might be a multi-frame response.
            - The method logs a message and continues iterating.

7. **Identify UDS Endpoint:**
    - If a valid response is received from a different address than the transmitted one, a UDS endpoint is potentially discovered on the current CAN ID.
        - The method logs a success message and extracts details from the response:
            - Source and destination CAN IDs.
            - Response payload in hexadecimal format.
        - A `TargetURI` object is constructed representing the discovered endpoint, incorporating relevant details like transport scheme, hostname, addresses (source and destination), extended addressing settings (if applicable), and potentially padding values (if used).
        - The discovered endpoint is appended to the `found` list.
        - The loop exits, as a UDS endpoint has been identified on the current CAN ID.

8. **Compile Results and Write to File:**
    - After iterating through the CAN ID range, the method logs the total number of discovered UDS endpoints.
    - It constructs the file path for storing the discovered endpoints in a text file named "ECUs.txt" within the `artifacts_dir` directory.
    - The `write_target_list` method is called asynchronously to write the list of discovered endpoints along with any associated database information (using `self.db_handler`) to the file.

9. **Optional: Query ECU Description (Diagnostics):**
    - If `args.query` is True, the method calls the `query_description` method to retrieve the ECU description for each discovered endpoint using the specified DID (Data Identifier) from `args.info_did`.
        
#### Usage

```
gallia discover uds isotp --start <START_ID> --stop <END_ID> --target <TARGET_URI>
```

**Example:**

This example command discovers UDS endpoints on a CAN bus using virtual interface vcan0 within a CAN ID range of 0x000 to 0x7FF, sending a default UDS PDU and logging discovered endpoints:

```
gallia discover uds isotp --start 0 --stop 0x7FF --target can-raw://vcan0
```

#### ISO-TP Details

[ISO-TP](https://www.iso.org/standard/66574.html) is a standard for a transport protocol on top of the [CAN bus](https://www.iso.org/standard/63648.html) system.
The CAN bus is a field bus which acts as a broadcast medium; any connected participant can read all messages.
On the CAN bus there is no concept of a connection.
Typically, there are cyclic messages on the CAN bus which are important for selected participants.
However, in order to implement a connection channel for the UDS protocol (which is required by law to be present in vecicles) the ISO-TP standard comes into play.
In contrast to DoIP special CAN hardware is required.
The ISO-TP protocol and the interaction with CAN interfaces is handled by the [networking stack](https://www.kernel.org/doc/html/latest/networking/can.html) of the Linux kernel.

##### ISO-TP addressing methods

ISO-TP provides multiple different addressing methods:
* normal addressing with normal CAN IDs,
* normal addressing with extended CAN IDs,
* extended addressing with normal CAN IDs,
* extended addressing with extended CAN IDs,
* the mentioned schemes but with CAN-FD below,
* …

```{note}
For the detailed explanation of all these addressing modes we refer to the relevant ISO standard documents or further documents or presentations which are available online.
```

The tester needs to make assuptions about what addressing scheme is used; otherwise the scan does not yield any results.
ISO-TP provides the following parameters:

* **source can_id**:
    * Without extended addressing: Often set to an address with a static offset to the destination can_id.
    * Extended addressing: Often set to a static value, e.g. `0x6f1`; a.k.a. *tester address*.
* **destination can_id**: 
    * Without extended addressing: Address of the ECU
    * Extended addressing: Somehow part of the ECU address, e.g. `0x600 | ext_address`
* **extended source address**: When extended addressing is in use, often set to a static value, e.g. `0xf1`.
* **extended destination address**: When extended addressing is in use, it is the address of the ECU.

The discovery procedure is dependent on the used addressing scheme.

## Session Scan

UDS has the concept of sessions.
Different sessions can for example offer different services.
A session is identified by a 1 byte session ID.
The UDS standard defines a set of well known session IDs, but vendors are free to add their own sessions.
Some sessions might only be available from a specific ECU state (e.g. current session, enabled/configured ECU features, coding, ...).
Most of those preconditions cannot be detected automatically and might require vendor specific knowledge.

The session scan tries to find all available session transitions.
Starting from the default session (0x01), all session IDs are iterated and enabling the relevant session is tried.
If the ECU replies with a positive response, the session is available.
In case of a negative response, the session is considered not available from the current state.
To detect sessions, which are only reachable from a session different to the default session, a recursive approach is used.
The scan for new sessions starts at each previously identified session.
The maximum depth is limited to avoid endless scans in case of transition cycles, such as `0x01 -> 0x03 -> 0x05 -> 0x03`.
The scan is finished, if no new session transition is found.

## Service Scan

The service scan operates at the UDS protocol level.
UDS provides several endpoints called *services*.
Each service has an identifier and a specific list of arguments or sub-functions.

In order to identify available services, a reverse matching is applied.
According to the UDS standard, ECUs reply with the error codes `serviceNotSupported` or `serviceNotSupportedInActiveSession` when an unimplemented service is requested.
Therefore, each service which responds with a different error code is considered available.
To address the different services and their varying length of arguments and sub-functions the scanner automatically appends `\x00` bytes if the received response was `incorrectMessageLengthOrInvalidFormat`.

## Identifier Scan

The identifier scan operates at the UDS protocol level; to be more specific it operates at the level of a specific UDS service.
Most UDS services need identifiers is input arguments.
For instance, the ReadDataByIdentifier service requires a data identifier input for the requested ressource.
In order to find out the available identifiers for a specific service the Identifier Scan is employed.

In order to identify available data identifiers, a reverse matching is applied.
According to the UDS standard, ECUs reply with the error codes `serviceNotSupported` or `serviceNotSupportedInActiveSession` when an unimplemented service is requested.
If the ECU responds with any of `serviceNotSupported`, `serviceNotSupportedInActiveSession`,`subFunctionNotSupported`, `subFunctionNotSupportedInActiveSession`, or `requestOutOfRange` the identifier is considered not available.

A few services such as RoutineControl offer a `subFunction` as well.
SubFunction arguments can be discovered with the same technique but the error codes for the reverse matching are different.
For discovering available subFunctions the following error codes indicate the subFunction is not available: `serviceNotSupported`, `serviceNotSupportedInActiveSession`, `subFunctionNotSupported`, or `subFunctionNotSupportedInActiveSession`.

Each identifier or subFunction which responds with a different error code is considered available.

## Memory Functions Scan

This scanner targets Electronic Control Units (ECUs) and explores functionalities that provide direct access to their memory.

### Functionality

The scanner focuses on the following Unified Diagnostic Service (UDS) services:

* **ReadMemoryByAddress (service ID 0x23):** Retrieves data from a specified memory location.
* **WriteMemoryByAddress (service ID 0x3D):** Writes data to a specified memory location.
* **RequestDownload (service ID 0x34):** Tester downloads a block of data from the ECU.
* **RequestUpload (service ID 0x35):** ECU uploads a block of data to the tester.

These services all share a similar packet structure, with the exception of WriteMemoryByAddress which requires an additional data field.
It iterates through a range of memory addresses and attempts to:

* Read or write data using the chosen UDS service.
* Handle potential timeouts during communication with the ECU.
* Analyze the ECU's response to these attempts, which might reveal vulnerabilities or security mechanisms.

The scanner offers several configuration options through command-line arguments to customize its behavior:
* Target diagnostic session (default: 0x03).
* Optionally verify and potentially recover the session before each memory access.
* Specify the UDS service to use for memory access (required, choices: 0x23, 0x3D, 0x34, 0x35).
* Provide data to write for service 0x3D WriteMemoryByAddress (8 bytes of zeroes by default).

### Usage

```
gallia scan uds memory --target <TARGET_URI> --sid <SID>
```

**Example:**

```
gallia scan uds memory --sid 0x23 --target "isotp://can2?is_fd=false&is_extended=true&src_addr=0x22bbfbfa&dst_addr=0x22bbfafb&tx_padding=0&rx_padding=0" --db ecu_test --session 1
```

The provided command invokes the scanner to utilize the UDS service `ReadMemoryByAddress` (service ID 0x23) on the target ECU reachable through the specified ISO-TP connection in session `0x01`. It will iterate through a range of memory addresses and attempt to read data from those locations. The results will be saved in a database file called `ecu_test`.

## Dump Security Access Seeds

The `dump-seeds` scanner attempts to retrieve security access seeds from the connected ECU. These seeds are (ideally) random values used by the ECU's security mechanisms. By capturing these seeds, attackers might be able to potentially bypass certain security checks or unlock higher access levels.

The scanner offers several functionalities:

* **Session Management:**
    * Can switch between diagnostic sessions on the ECU based on the provided session ID.
    * Optionally verifies the current session before proceeding.
    * Re-enters the session after potential ECU resets.
* **Seed Request:**
    * Requests security access seeds at a specified level from the ECU.
    * Allows attaching additional data to the seed request message.
    * Handles timeouts and errors that might occur during communication with the ECU.
* **Key Sending (Optional):**
    * Simulates sending a key filled with zeros after requesting a seed.
    * This technique might bypass certain brute-force protection mechanisms implemented by the ECU.
* **ECU Reset (Optional):**
    * Can be configured to periodically reset the ECU.
    * This aims to overcome limitations imposed by the ECU, such as seed rate limiting.
    * Handles ECU recovery and reconnection after reset.

### Usage

The seed dumper is invoked using the following command:

```
gallia scan uds dump-seeds --target <TARGET_URI> [OPTIONS]
```

**Example:**

This example demonstrates how to capture seeds from security level 0x11 with session 0x02, resetting the ECU every 10th seed request, and running for 30 minutes:

```
gallia scan uds dump-seeds --target "isotp://vcan0?is_fd=false&is_extended=false&src_addr=0x701&dst_addr=0x700" --session 0x02 --data-record 0xCAFE00 --level 0x11 --reset 10 --duration 30 --db ecu_test
```

This command would:
* Connect to the ECU specified by `<TARGET_URI>`.
* Switch to diagnostic session 0x02 (if possible).
* Request seeds from security level 0x11 with data record 0xCAFE00. (`27 11 CA FE 00`)
* Reset the ECU after every 10th seed request.
* Run for 30 minutes (or indefinitely if `--duration` is not set).
* Log the results in a database file called `ecu_test`

The dumped seeds will be written to a file named "seeds.bin" located in the scanner's artifacts directory.