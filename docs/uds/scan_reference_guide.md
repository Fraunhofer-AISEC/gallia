# Scan Reference Guide

This reference guide provides detailed information on the various scan modes of `gallia` used to assess the security and diagnostic capabilities of ECUs (Electronic Control Units) in vehicles. Each section outlines the purpose, message structure, success and failure criteria, and the type of information to include in test reports for each scan.

### Terminology Definition

* **ECU** - Electronic Control Unit, a piece of hardware that could contain multiple diagnostic endpoints/servers on various interfaces (UDS on CAN, DoIP, XCP, etc.)
* **UDS Server** - a single UDS source-target address pair. A single ECU can have multiple UDS servers on different communication channels or interfaces.

## Discovery Scan

### Purpose

Identify ECUs (Electronic Control Units) present on a vehicle network, either through DoIP (Diagnostics over IP) or ISO-TP (ISO Transport Protocol) over CAN (Controller Area Network). This is a foundational step for further diagnostic and security testing.

To avoid identifying unrelated CAN traffic as UDS endpoints, the scan observes the bus for a period to identify regular, non-diagnostic messages. These messages are then filtered out, allowing the scan to focus on potential UDS responses.

### Messages Sent

* **DoIP:**
    * `RoutingActivationRequest`: Initializes the DoIP connection.
    * `DiagnosticMessage`: Contains a standard UDS (Unified Diagnostic Services) request (e.g., `10 01` for session control) sent to a range of target addresses.
* **ISO-TP (CAN):**
    * ISO-TP frames containing standard UDS requests (first `3E 00` for TesterPresent and subsequently `10 01` for DiagnosticSessionControl) are sent to a specified range of CAN IDs.

### Success Criteria

* **DoIP:** A valid UDS response from an ECU indicates its presence at the tested target address.
* **ISO-TP (CAN):** A valid ISO-TP response (not an error frame) from a CAN ID indicates a potential UDS endpoint.

### Failure Criteria

* **DoIP:** No response (e.g., indicating no ECU at that address), or a network-level error.
* **ISO-TP (CAN):** No response, an ISO-TP error frame, or a response only seen in the idle traffic (suggesting a non-UDS node).

### Report Information

* **Discovered ECUs (DoIP):**
    * List of DoIP target addresses (IP addresses and ports) where ECUs were found.
    * ECU identification details (if obtained through subsequent UDS requests).
* **Discovered ECUs (ISO-TP):**
    * List of CAN IDs where UDS endpoints were discovered.
    * Source and destination CAN IDs used for communication.
    * ECU identification details (if obtained through further diagnostic requests).
* **Unusual Responses:** Any responses that deviate from the standard UDS or ISO-TP specifications, which might indicate non-standard ECU implementations.

### Additional Information (for ISO-TP)

* **Addressing Mode:** Specify whether normal or extended addressing was used for ISO-TP.
* **Tester Address:** If applicable, mention the tester address used in extended addressing mode.
* **Querying ECU Description:** If enabled, note if the scan queried ECU descriptions using a specific DID (Data Identifier) and include the retrieved descriptions.

### Example Report Snippet (DoIP)

```
Discovery Scan Report (DoIP)

Discovered ECUs:

* Target Address: 192.168.0.10:13400
* ECU Identification: Engine Control Module (via DID read F190)
* Target Address: 192.168.0.20:13400
* ECU Identification: Transmission Control Module (via DID read F190)

Analysis: Two ECUs were successfully discovered on the DoIP network. Further diagnostic testing is recommended to assess their functionality and security.
```

### Example Report Snippet (ISO-TP)

```
Discovery Scan Report (ISO-TP)

Discovered ECUs:

* CAN ID: 0x7E8 (Source: 0x7E0, Target: 0x7E8)
* ECU Identification: Body Control Module (via DID read F190)
* CAN ID: 0x7E8 (Source: 0x7FF, Target: 0x7E8)
* ECU Identification: Body Control Module (via DID read F190)
* CAN ID: 0x72A (Source: 0x7FF, Target: 0x72A)
* ECU Identification: Not obtained (further testing required)

Analysis: Three potential UDS endpoints were discovered on the CAN bus. Two of them were identified as the same physical ECU. Multiple CAN IDs pointing to the same ECU (in this case, the Body Control Module) are common and often represent different diagnostic addresses or functionalities within the ECU. Additional diagnostic requests are needed to identify the other ECU and assess their capabilities.
```

## Session Scan

### Purpose

Discover all available diagnostic sessions within a UDS server and the valid transition paths between them. This scan helps assess the ECU's state management and identify potential vulnerabilities related to unauthorized access to privileged sessions.

### Messages Sent

* **DiagnosticSessionControl (0x10):** This request is used to attempt transitions to different sessions. It's sent with varying session IDs (0x01 to 0x7F) to check for supported sessions.

### Success Criteria

* **Positive Response:** The ECU responds with a positive acknowledgment (`50 xx`) to the session change request, indicating that the requested session is available and the transition was successful.
* **Negative Response:** The ECU responds with a specific negative response code:
    * **conditionsNotCorrect (0x22):** Session exists, but the conditions to enter the requested session are not met.
    * **subFunctionNotSupportedInActiveSession (0x7E):** The session is supported but cannot be transitioned into from the current session.

### Failure Criteria

* **Negative Response:** The ECU responds with a negative response code, such as:
    * **subFunctionNotSupported (0x12):** The session ID is not supported.
* **Timeout:** The ECU fails to respond within the expected time, suggesting the session transition was not successful.

### Report Information

* **Entered Sessions:** A list of all sessions successfully entered during the scan, along with the path (sequence of transitions) used to reach each session.
* **Session Transition Failed:** A list of sessions that could not be entered (but exist), either due to negative responses or conditions not being met, along with the associated error codes.
* **Session-Specific Details:**
    * **Session Name:** If known, the name or description of each discovered session (e.g., "Default Session," "Extended Session," etc.).
    * **Entry Requirements:** If available, any conditions or prerequisites that need to be met to enter a specific session.
* **Error Handling:** Details of how the scan handled "conditionsNotCorrect" errors (using hooks) and ECU resets, if applicable.
* **Analysis:**  A summary of the scan results, emphasizing any unusual session behavior, potential security vulnerabilities, or non-standard session transitions.

### Example Report Snippet

```
Session Scan Report

Sessions Entered:

- Default Session (0x01)
- Extended Session (0x03) - Accessible from Default Session (0x01)
- Programming Session (0x02) - Accessible from Extended Session (0x03)

Session Transitions:

Default Session (0x01) -> Extended Session (0x03) -> Programming Session (0x02)

Session Transition Failed (existing, but not entered):

- Session 0x41 (conditionsNotCorrect)
- Session 0x42 (securityAccessDenied)

Analysis: The ECU supports standard sessions with a linear transition path. Session 0x41 might be accessible under specific conditions not tested in this scan. Session 0x42 might be accessible after a securityAccess condition satisfaction.
```

## Reset Scan

### Purpose

Evaluate the resilience and behavior of an ECU (Electronic Control Unit) under various reset conditions. This scan helps identify potential vulnerabilities in reset handling and assess the impact of different reset types on the ECU's state and functionality.

### Messages Sent

* **ECUReset (0x11):** This request is sent with varying sub-function parameters (0x01 to 0x7F) to trigger different types of resets as defined in the UDS standard.

### Success Criteria

* **Positive Response:** The ECU acknowledges the reset request with a positive response (`51 xx`) indicating a successful reset.
* **Expected Recovery:** After a successful reset, the ECU recovers to a known, default state (often the default session) or a state as specified by the sub-function.

### Failure Criteria

* **Negative Response:** The ECU responds with a negative response code, such as:
    * **subFunctionNotSupported (0x12):**  The specific reset sub-function is not supported.
    * **conditionsNotCorrect (0x22):** Conditions are not met for the requested reset.
* **Timeout:** The ECU fails to respond within the expected time, suggesting the reset may have caused an issue.
* **Unexpected Recovery:** The ECU recovers to an unexpected state after reset, potentially indicating a security flaw.

### Report Information

* **Supported Reset Sub-functions:** A list of all reset sub-functions that resulted in a positive response and expected recovery behavior.
* **Session Impact:** If the scan tests multiple sessions, details on how resets affect the active session and whether the ECU correctly returns to the intended session.
* **Unexpected Behavior:** A description of any anomalies observed during the scan, such as the ECU recovering to an unexpected session or state after reset.
* **Potential Vulnerabilities:** Any identified cases where a reset triggers an unexpected behavior that could be exploited for malicious purposes (e.g., transitioning to a privileged session without proper authorization).

### Example Report Snippet

```
Reset Scan Report

Default Session (0x01):
- Supported Resets: HardReset (0x01), KeyOffOnReset (0x02), SoftReset (0x05)
- Unsupported Resets: (0x11) - securityAccessDenied
- Unexpected Behavior: ECU remained in Extended Session after SoftReset

Extended Session (0x03):
- Supported Resets: HardReset (0x01)
- Timeouts: EnableRapidPowerShutDown (0x04), ResetToBootLoader (0x07)

Analysis: 
- The ECU supports basic reset functions in the Default Session.
- In the Extended Session, several resets either timed out or resulted in unexpected behavior, suggesting potential vulnerabilities. Further investigation is recommended.
```

## Service Scan

### Purpose

Identify the UDS services supported by an ECU. This scan helps assess the ECU's diagnostic capabilities and identify potential entry points for further security analysis.

### Messages Sent

* **Service Requests:** The scan sends requests for all standard UDS service IDs (0x00 to 0x7F). If configured, it also includes service IDs with the "SuppressPositiveResponse" bit set (up to 0xFF). The UDS server should not display behavior different to a request without the suppress bit, but it is important to test all edge-cases.
* **Payload Variations:** For services potentially requiring additional parameters (such as WriteDataByIdentifier), the scan varies the payload length to accommodate different payload structures.

### Success Criteria

* **Positive Response:** The ECU acknowledges the service request with a positive response specific to that service.
* **Negative Response (Generic):** The ECU responds with a negative response code other than `serviceNotSupported` or `serviceNotSupportedInActiveSession`. Each service which responds with a different error code is considered available.

### Failure Criteria

* **Negative Response (Specific):** According to the UDS standard, ECUs reply with the error codes `serviceNotSupported` or `serviceNotSupportedInActiveSession` when an unimplemented service is requested.
* **Timeout:** The ECU doesn't respond within the expected time frame, potentially indicating a lack of support for the service.

### Report Information

* **Supported Services:** A comprehensive list of all positively identified services, categorized by the diagnostic session in which they were found (if multiple sessions were scanned).
* **Illegal Responses:** In case of an illegal response, providing additional insight into the ECU's behavior.

### Example Report Snippet

```
Service Scan Report

Default Session (0x01):
DiagnosticSessionControl (0x10), ECUReset (0x11), ReadDataByIdentifier (0x22),

Programming Session (0x02):
DiagnosticSessionControl (0x10), ECUReset (0x11), SecurityAccess (0x27), WriteDataByIdentifier (0x2E),

Analysis: The ECU supports standard diagnostic services in the default session. SecurityAccess and programming-related services are only available in the programming session.
```

## Identifier Scan

### Purpose
Read data from data identifiers (DIDs) to assess potential sensitive data or discover sub-functions supported by a specific UDS service within a UDS server.

### Target Services
* `0x27`: SecurityAccess
* `0x22`: ReadDataByIdentifier
* `0x2e`: WriteDataByIdentifier
* `0x31`: RoutineControl

### Messages Sent
* UDS requests tailored to the selected service.
    * Requests contain the service ID, followed by the DID or sub-function being tested. 
    * Optionally, a custom payload can be appended to the request.

* **Service-Specific Requests:** The scan sends requests using one of the targeted services, along with parameters like:
    * **DID/sub-function:** The specific sub-function to target (e.g., try to read, write or launch).
    * **Custom payload (optional):** A custom payload can be appended to the request.

### Success Criteria
* **Positive Response:** The ECU acknowledges the DID or sub-function with a positive response specific to the service. This indicates that the DID/sub-function is valid and supported.

### Failure Criteria
* **Negative Response:** The ECU responds with a negative response code. These responses are categorized as:
    * **Service-Specific:** Negative responses that are expected based on the selected service and indicate that the DID/sub-function is not supported or unavailable. Examples include `requestOutOfRange`, `subFunctionNotSupported`, or `serviceNotSupportedInActiveSession`.
    * **Other:** Other negative response codes might signal unexpected behavior or issues with the communication.
    * **Timeout**: The ECU does not respond within the expected timeframe. This might indicate that the DID/sub-function is not supported, or there are communication issues.
    * **Illegal Response**: The ECU responds with an unexpected or invalid response that doesn't conform to the UDS standard.

### Report Information
* **Supported DIDs/Sub-functions:** A list of all positively identified DIDs or sub-functions, organized by the session in which they were found (if multiple sessions were scanned).
* **Session Details:** If multiple sessions were tested, a breakdown of supported identifiers per session, along with any session-switching issues encountered.
* **Analysis:** A brief analysis highlighting any patterns or anomalies found in the scan results, potentially pointing towards security vulnerabilities or non-standard implementations.

### Example Report Snippet

```
Identifier Scan Report

Service: ReadDataByIdentifier (0x22)

Default Session (0x01):
F180: 56 31 2E 35 2E 34 = V1.5.4
F190: 31 47 31 4A 43 35 32 34 58 59 37 32 31 38 38 36 39 = 1G1JC524XY7218869

Extended Session (0x03):
F180: 56 31 2E 35 2E 34 = V1.5.4
F181: 50 72 65 52 65 6C 65 61 73 65 56 31 2E 35 2E 34 = PreReleaseV1.5.4
F190: 31 47 31 4A 43 35 32 34 58 59 37 32 31 38 38 36 39 = 1G1JC524XY7218869
F191: Timeout
F192: Timeout

Analysis: The ECU supports most standard DIDs in both sessions. Timeouts in the extended session might indicate communication issues or intentional restrictions.
```

## Memory Scan

### Purpose

Test and evaluate UDS services that allow direct access to an ECU's memory. By interacting with services like `ReadMemoryByAddress` and `WriteMemoryByAddress`, this scan helps identify potential vulnerabilities in memory access control mechanisms and uncover sensitive data or executable code that might be stored in the ECU's memory.

### Target Services

* `0x23`: ReadMemoryByAddress
* `0x3D`: WriteMemoryByAddress
* `0x34`: RequestDownload
* `0x35`: RequestUpload

### Messages Sent

* **Service-Specific Requests:** The scan sends requests using one of the targeted services, along with parameters like:
    * **Memory Address:** The location in memory to read from or write to.
    * **Memory Size (if applicable):** The amount of data to read or write.
    * **Data (for WriteMemoryByAddress):** The data to be written.

### Success Criteria

* **Positive Response:** The ECU responds with the requested data (for read operations) or acknowledges the successful write operation (for write operations). This indicates the service is functional and the specified memory location is accessible.

### Failure Criteria

* **Negative Response:** The ECU responds with an error code, such as:
    * `requestOutOfRange`: The specified memory address is outside the valid range.
    * `generalReject`: The service is not supported or the request is invalid.
    * `securityAccessDenied`:  The current security level doesn't permit the requested memory access.
    * `conditionsNotCorrect`: Certain preconditions (like a specific session) haven't been met for memory access.

* **Timeout:** The ECU doesn't respond within the expected time, suggesting the service is not available or the memory address is not accessible.

### Report Information

* **Tested Memory Range:** The range of memory addresses that were scanned.
* **Accessible Memory:** A list of memory addresses that responded positively to read or write requests, potentially indicating regions without strict access controls.
* **Inaccessible Memory:** A list of memory addresses that resulted in negative responses or timeouts, suggesting protected or unavailable areas.
* **Security Observations:**  Details of any security mechanisms encountered (e.g., securityAccessDenied responses) and potential vulnerabilities discovered.
* **Retrieved Data:** If data was successfully read using `ReadMemoryByAddress`, a sample of the retrieved data might be included, provided it doesn't contain sensitive information.

### Example Report Snippet

```
Memory Scan Report

Service Tested: ReadMemoryByAddress (0x23)
Session: Extended Diagnostic Session (0x03)

Memory Range Tested: 0x000000 - 0x001000

Accessible Memory:
- 0x000000 - 0x0000FF (responded with data)

Inaccessible Memory:
- 0x000100 - 0x001000 (requestOutOfRange)

Security Observations: 
- Memory range 0x000800 - 0x000FFF returned securityAccessDenied, indicating potential sensitive data.

Recommendations:
- Further investigate the accessible memory range to determine if it contains sensitive information.
- Attempt to bypass the securityAccessDenied response in the protected memory range to assess potential vulnerabilities.
```

## Seed Dumping Scan

### Purpose

Extract security access seeds from the ECU (Electronic Control Unit) to analyze the ECU's security mechanisms and potentially identify vulnerabilities. Seeds are random values used for cryptographic operations in security access procedures.

### Targeted Service

* `0x27`: SecurityAccess (specifically the "Request Seed" and "Send Key" sub-functions)

### Messages Sent

* **RequestSeed (`27 01`):** Requests a seed from a specific security level, optionally including a custom data record.
* **SendKey (`27 02`):** (Optional) Sends a key (typically derived from the seed) to the ECU, usually with the intent to bypass brute-force protection mechanisms.
* **ECUReset (0x10):** (Optional) Sends a restart request to the ECU with the intent to bypass brute-force protection mechanisms.

### Success Criteria

* **Valid Seed Retrieval:** The ECU responds with a positive response (`67 xx`) containing a seed value.

### Failure Criteria

* **Negative Response:** The ECU responds with a negative response code, such as:
    * **securityAccessDenied (0x33):** Insufficient security level to access the requested seed.
    * **requiredTimeDelayNotExpired (0x37):** A time delay is required before requesting another seed.
    * **exceededNumberOfAttempts (0x36):** Too many incorrect keys have been sent for the current security level.
* **Timeout:** The ECU fails to respond within the expected time, indicating potential communication issues or seed request throttling.

### Report Information

* **Session:** The diagnostic session used for seed extraction.
* **Security Level:** The security level from which seeds were requested.
* **Number of Seeds Dumped:** The total number of seeds successfully retrieved.
* **Seed Dump Rate:** The rate at which seeds were dumped (e.g., seeds per second).
* **Dump Duration:** The total time taken for the seed dumping process.
* **Data Record:** If used, the data record appended to seed requests.
* **Zero Key Strategy:** Whether zero-filled keys were sent (and if successful).
* **Reset Strategy:** If ECU resets were used to bypass rate limiting, details on the reset frequency and success.
* **Unusual Responses:** Any unexpected negative responses or patterns that might indicate non-standard ECU behavior or potential security vulnerabilities.
* **Analysis:** Assessment of the seed randomness, potential weaknesses in the seed generation algorithm, and any observed limitations in the ECU's security access implementation. 

### Example Report Snippet

```
Seed Dumping Scan Report

Session: Extended Diagnostic Session (0x03)
Security Level: 0x11
Number of Seeds Dumped: 26000
Total Seed Dump Rate: 20.8 seeds/minute
Dump Duration: 120 minutes

Appended Data Record after `27 xx`: 0x12345678
Zero Key Strategy: Not Used
Reset Strategy: Used (every 10 seeds)

Filename: seeds_03_sa11.bin

Analysis: 
- The ECU successfully responded to seed requests with valid seeds.
- The reset strategy was effective in bypassing the ECU's rate limiting.
- Further analysis of the dumped seeds is required to assess their randomness and potential vulnerabilities.
```