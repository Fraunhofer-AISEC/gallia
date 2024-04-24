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

[ISO-TP](https://www.iso.org/standard/66574.html) is a standard for a transport protocol on top of the [CAN bus](https://www.iso.org/standard/63648.html) system.
The CAN bus is a field bus which acts as a broadcast medium; any connected participant can read all messages.
On the CAN bus there is no concept of a connection.
Typically, there are cyclic messages on the CAN bus which are important for selected participants.
However, in order to implement a connection channel for the UDS protocol (which is required by law to be present in vecicles) the ISO-TP standard comes into play.
In contrast to DoIP special CAN hardware is required.
The ISO-TP protocol and the interaction with CAN interfaces is handled by the [networking stack](https://www.kernel.org/doc/html/latest/networking/can.html) of the Linux kernel.

For a discovery scan it is important to distinguish whether the tester is connected to a filtered interface (e.g. the OBD connector) or to an unfiltered interface (e.g. an internal CAN bus).
In order to not confuse the discovery scanner, the so called *idle traffic* needs to be observed.
The idle traffic consists of the mentioned cyclic messages of the can bus.
Since there is no concept of a connection on the CAN bus itself and the parameters for the ISO-TP connection are unknown at the very first stage, an educated guess for a deny list is required.
Typically, `gallia` waits for a few seconds and observes the CAN bus traffic.
Subsequently, a deny filter is configured which filters out all CAN IDs seen in the idle traffic.

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

The discovery procedure is dependend on the used addressing scheme.
From a high level perspective, the destination id is iterated and a valid payload is sent.
If a valid answer is received, an ECU has been found.

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

## Security Access Level Scan

This type of scan searches for available security access levels (SAs) within a UDS server on specified sessions. Security access levels are used to restrict access to certain UDS services and subfunctions. By identifying the available SAs, an attacker might gain insights into the ECU's security mechanisms and potentially exploit them to elevate privileges.

The `gallia` tool offers a class `SALevelScanner` to perform this security access level scan.

### Usage

The scanner can be invoked using the following command:

```
gallia scan uds security-access [OPTIONS]
```

**Arguments:**

*  `--target <TARGET_URI>`: URI specifying the connection details to the target ECU (e.g., `isotp://vcan0?is_fd=false&is_extended=false&src_addr=0x701&dst_addr=0x700`).
*  `--sessions <SESSION_ID>` (optional): Restricts the scan to specific sessions (space-separated list, e.g., `--sessions 1 2 3`). If not specified, only the current session is scanned.
*  `--check-session` (optional): Additionally verifies the current session before each SA level test (only applicable if `--sessions` is used).
*  `--scan-response-ids` (optional): Includes ID information in scan results for messages with the reply flag set.
*  `--auto-reset` (optional): Resets the ECU with the `UDS ECU Reset` service before every request.
*  `--skip <SKIP_SPEC>` (optional): Skips specific subfunctions per session. Refer to the following section for details on the skip specification format.

**Skip Specification Format**

The `--skip` argument allows you to exclude specific subfunctions from the scan on a per-session basis. The format for specifying skips is:

```
<SESSION_ID>:<SUBFUNCTION_RANGES>
```

* `<SESSION_ID>`: The diagnostic session ID (hexadecimal value).
* `<SUBFUNCTION_RANGES>`: Comma-separated list of subfunction ranges or individual subfunctions to skip. Each range or subfunction is specified as a hexadecimal value. A range can be defined using a hyphen (`-`) between the start and end subfunction values (inclusive).

Here are some examples of valid skip specifications:

* `0x01:0x0F` - Skips all subfunctions from 0x01 to 0x0F (inclusive) in session 0x01.
* `0x10-0x2F` - Skips subfunctions from 0x10 to 0x2F (inclusive) in the current session.
* `0x01:0x05,0x10` - Skips subfunctions 0x01 to 0x05 and 0x10 in the current session.
* `0x01:0x0F,0x10-0x2F:0x03` - Skips subfunctions 0x01 to 0x0F, 0x11 to 0x2F (inclusive), and 0x03 in session 0x01.

**Examples**

* Scan all available sessions for security access levels:

```
gallia scan uds security-access
```

* Scan sessions 0x01 and 0x02, verify the session before each test, and skip subfunctions 0x01 to 0x0A in session 0x01:

```
gallia scan uds security-access --sessions 0x01,0x02 --check-session --skip 0x01:0x0A
```

* Scan all sessions, include reply IDs in scan results, and reset the ECU before each request:

```
gallia scan uds security-access --scan-response-ids --auto-reset
```

### Scan Process

The `SALevelScanner` performs the following steps during a security access level scan:

1. **Parses command-line arguments:** The scanner processes the provided options and arguments to determine the target sessions, skip specifications, and other configuration settings.
2. **Iterates through sessions:**
   * If no specific sessions are provided (`--sessions` not used), the scanner iterates through all available sessions. Otherwise, it focuses on the specified sessions.
3. **Session change (optional):** For each session included in the scan, the scanner attempts to establish the desired session using the `UDS SetSession` service. If session verification is enabled (`--check-session`), the scanner additionally verifies the current session before proceeding. In case of errors during session change, the scanner logs a warning and moves to the next session (if applicable).

## Memory Scan

TODO
