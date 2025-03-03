<!--
SPDX-FileCopyrightText: AISEC Pentesting Team

SPDX-License-Identifier: CC0-1.0
-->

# Virtual ECUs

For testing purposes, there exists the possibility to spawn virtual ECUs, against which the scanners can be run.
The virtual ECUs can however also be used independently of the remaining Gallia tools.

The generic command to create a virtual ECU is as follows:

```shell-session
$ gallia script vecu [vecu-arguments] <transport> <model> [model-arguments]
```

The virtual ECUs support different transport schemes and answering models, 
which are explained in the following sections.

## transport

The virtual ECU model is separated from the transport layer that is used for communication.
Currently, two different transport types are supported.
For each of them, a corresponding transport scheme exists on the scanner side, 
which has to be used to enable communication between the scanner and the virtual ECU.

### tcp-lines

The transport scheme which is the easiest to use is the tcp-lines scheme.
It requires no additional setup and can be used immediately.
When using this transport scheme, the virtual ECU can handle requests from multiple UDS clients, 
but conversely a scanner can only talk to a single virtual ECU.
For most scanners this is the intended behavior.
For discovery scanners instead, the tcp-lines transport is not suitable.

For example, a random virtual ECU, which uses the tcp-lines protocol for communication 
and listens for IPv4 connections on port 20162 can be started with the following command:

```shell-session
$ gallia script vecu "tcp-lines://127.0.0.1:20162" rng
```

For IPv6, the command would look as follows:

```shell-session
$ gallia script vecu "tcp-lines://[::1]:20162" rng
```

### iso-tp

The iso-tp scheme operates on an existing can interface, which can be a physical interface or a virtual interface.
The following commands can be used to set up a virtual CAN interface with the name *vcan0*:

```shell-session
# ip link add dev vcan0 type vcan
# ip link set up vcan0
```

In contrast to the tcp-lines approach, 
using the iso-tp transport scheme allows to simulate a whole bus of several virtual ECUs, 
and is therefore also suitable for testing discovery scanners.

For example, two random virtual ECUs, which uses the iso-tp protocol for communication 
and use the *vcan0* interface can be started with the following commands:

```shell-session
$ gallia script vecu "isotp://vcan0?src_addr=0x6aa&dst_addr=0x6f4&rx_ext_address=0xaa&ext_address=0xf4&is_fd=false" rng
$ gallia script vecu "isotp://vcan0?src_addr=0x6bb&dst_addr=0x6f4&rx_ext_address=0xbb&ext_address=0xf4&is_fd=false" rng
```

## model

There are currently two different types of ECU models, which can be used together with any of the supported transports.

### rng

This type of model, creates an ECU, with a random set of supported sessions, services, sub-functions and identifiers, 
where applicable.
By default, this model makes use of all available default behaviors, 
thereby offering a very standard conformant behavior out of the box.
As with any model, these default mechanisms can be disabled via the *vecu-options*.
It can be further customized by specifying mandatory as well as optional sessions and services.
Additionally, the probabilities which are used to compute the previously mentioned set of available 
functionality can be altered.

For example, a random virtual ECU with no customization can be created with the following command:

```shell-session
$ gallia vecu "tcp-lines://127.0.0.1:20162" rng
Storing artifacts at ...
Starting ...
Initialized random UDS server with seed 1623483675214623782
    "0x01": {
        "0x01 (ShowCurrentData)": null,
        "0x02 (ShowFreezeFrameData)": null,
        "0x04 (ClearDiagnosticTroubleCodesAndStoredValues)": null,
        "0x07 (ShowPendingDiagnosticTroubleCodes)": null,
        "0x09 (RequestVehicleInformation)": null,
        "0x10 (DiagnosticSessionControl)": "['0x01']",
        "0x14 (ClearDiagnosticInformation)": null,
        "0x27 (SecurityAccess)": "['0x29', '0x2a', '0x3f', '0x40', '0x63', '0x64']",
        "0x31 (RoutineControl)": "['0x01', '0x02', '0x03']",
        "0x3d (WriteMemoryByAddress)": null
    }
}
```

After the startup, the output shows an overview of the supported sessions, services and sub-functions.
In this case only one session with ten services is offered.

To enable reproducibility, at the startup, the output shows the seed, which has been used to initialize the random 
number generator.
Using the same seed in combination with the same arguments, one can recreate the same virtual ECU:

```shell-session
gallia vecu "tcp-lines://127.0.0.1:20162" rng --seed <seed>
```

The following command shows how to control the selection of services, by altering the mandatory and optional services, 
as well as the probability that determines, how likely one of the optional services is included. 
The same is possible for services.
For other categories, only the probabilities can be changed.

```shell-session
$ gallia vecu "tcp-lines://127.0.0.1:20162" rng --mandatory_services "[DiagnosticSessionControl, ReadDataByIdentifier]" --optional_services "[RoutineControl]" --p_service 0.5
Storing artifacts at ...
Starting ...
Initialized random UDS server with seed 222579011926250596
{
    "0x01": {
        "0x10 (DiagnosticSessionControl)": "['0x01', '0x46']",
        "0x22 (ReadDataByIdentifier)": null,
        "0x31 (RoutineControl)": "['0x01', '0x02', '0x03']"
    },
    "0x46": {
        "0x10 (DiagnosticSessionControl)": "['0x01']",
        "0x22 (ReadDataByIdentifier)": null
    }
}
```

### db

This type of model creates a virtual ECU that mimics the behavior of an already scanned ECU.
This functionality is based on the database logging of the scanners.
For each request that the virtual ECU receives, it looks up if there is a corresponding request and response pair in 
the database, which also satisfies other conditions, such as a matching ECU state.
By default, it will return either the corresponding response, or no response at all, if no such pair exists.
As with any model, default ECU mechanisms, such as a default request or correct handling of the 
suppressPosRespMsgIndicationBit are supported, but are disabled by default.
They might be particularly useful to compensate for behavior, that is not intended to be handled explicitly, 
while being able to include the corresponding ECU in the testing procedure.

When using the db model, the virtual ECU requires the path of the database to which scan results have been 
logged for the corresponding ECU.
For example, a virtual ECU that mimics the behavior of an ECU, 
that was logged in */path/to/db* can be created with the following command:

```shell-session
$ gallia vecu "tcp-lines://127.0.0.1:20162" db /path/to/db
```

If the database contains logs of multiple ECUs, one particular ECU can be chosen by its name.
Note, that the name is not filled in automatically 
and may have to be manually added and referenced in one or more addresses.
Additionally, it is possible to include only those scan runs, for which the ECU satisfied a set of properties.
For example, the following command creates a virtual ECU that mimics the behavior of the ECU *XYZ* based on the logs 
in */path/to/db* where the *software_version* was *1.2.3*:

```shell-session
$ gallia vecu "tcp-lines://127.0.0.1:20162" db /path/to/db --ecu "XYZ" --properties '{"software_version": "1.2.3"}'
```
