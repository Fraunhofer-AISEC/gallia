# Introduction

Gallia is a comprehensive penetration testing toolchain for cars.
The scope of the toolchain is conducting penetration tests from a single ECU up to whole cars, with the main focus on the UDS interface.

The initial development was publicly sponsored by the German Federal Ministry of Education and Research, as part of the SecForCARs Project ([https://www.secforcars.de/](https://www.secforcars.de/)).
A short presentation and demo video can be found at: [https://www.secforcars.de/demos/10-automotive-scanning-framework.html](https://www.secforcars.de/demos/10-automotive-scanning-framework.html)

## Artifacts Folder Structure

Gallia uses its own folder structure to store its scan results (called artifacts).
The structure is as follows:
```
<Scanner Name>
- run-<timestamp>
- LATEST -> <latest run dir>
```

Every scan run creates the following artifact files:

| File                   | Description                            |
|------------------------|----------------------------------------|
| `OUTPUT.zstd`          | Compressed log file                    |
| `META.json`            | Information about the executed Scanner |
| `ecu_params_pre.json`  | ECU parameters read before the scan    |
| `ecu_params_post.json` | ECU parameters read after the scan     |
| `*.pcap.gz`            | Network capture                        |


## Discover Endpoints
When physically connected to the ECU, we first need to identify all available endpoints on the DUT.
Depending on the target protocol, different discover scanner are provided:
* `gallia discover-can-ids` (UDS)
* `gallia discover-endpoints` (UDS)
* `gallia discover-iso-tp-addr` (UDS)
* `discover-xcp` (XCP)

The identified endpoints are stored in the `ECUs.txt` artifact file.

## UDS Scanner

The following table shows the most important UDS scanner.
For a compleat list, please have a look at the help page.

| Scanner            | Description                                             |
|--------------------|---------------------------------------------------------|
| `scan-services`    | Iterate sessions and services and find endpoints        |
| `scan-sessions`    | Iterate Sessions (recursively)                          |
| `scan-identifiers` | This scanner scans DataIdentifiers of various services. |

## Database

Gallia can log all its scan result into a sqlite database.
For more details see: [Database](database)
