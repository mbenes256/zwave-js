# Overview

This project is a minimalist implementation of the Z-Wave API in Javascript. The goal is to control a simple home automation network
with light switches and motion sensors, garage door, etc and be able to integrate with an HTTP server.
I wanted to use Deno instead of Node.js, but the [full-featured Z-Wave Javascript implementation](https://github.com/zwave-js)
did not run on Deno at the time, plus it is very large - 128 npm modules for 60MB! Also Node security and privacy is a concern.

This code is mainly for programmers who want to write automation using javascript rather than GUIs.

Below is a list of commands and classes implemented. More classes can be added with the help
of the public [specification](https://www.silabs.com/wireless/z-wave/specification) docs.

Main features:
 - Standalone ES modules with no external dependencies or FFI (less than 70kB)
 - Uses SubtleCrypto API for encryption
 - Limited set of API and device commands
 - Security (S0 and S2)
 - Singlecast only

API commands supported:
 - Soft Reset
 - Set Default (erase network)
 - API Setup (Set TX Status Report, Set NodeID Base Type)
 - Get Init Data (get list of nodes)
 - Get Network IDs from Memory (get API module node ID)
 - Add Node to Network (including S0 and S2 bootstrap)
 - Remove Specific Node From Network
 - Is Node Failed
 - Remove Failed Node
 - Application Update
 - Bridge Controller Node Send Data
 - Bridge Command Handler

Device command classes supported:
 - Basic
 - Switch Binary
 - Sensor Binary
 - Multi Channel
 - Configuration
 - Notification
 - Battery
 - Wake Up
 - Version
 - Security (S0)
 - Security2 (S2)
 - Association
 - Association Group Info
 - Central Scene
 - Zwave Plus Info

Running on Ubuntu Linux / Deno 1.36.1 using this hardware:
 - Aeotec Z-Stick 7
 - Fibaro Smart Implant
 - Homeseer HS-PA100+ Plug-In Switch
 - Honeywell UltraPro Z-Wave Plus Smart Light Switch
 - Ecolink PIRZWAVE2.5 Z-Wave Plus Motion Sensor
 - GE Enbrighten Z-Wave Plus Smart Outlet Receptacle
 - ZOOZ ZEN17 Relay
 - ZOOZ ZEN34 Remote Switch
 - Homeseer HS-DS100+ Door/window Sensor

# Usage Examples

## Serial Port Access

The user is responsible for managing serial port access. The following is an example code compatible with Deno running on Linux.
The API will call the send and receive callback functions to send and receive from the serial port.

```javascript
function serial_init(dev_file) {
    // configure serial port
    const stty_args = ["-F", dev_file, "raw", "-parenb", "cs8", "-cstopb", "115200"];
    const res = new Deno.Command("/usr/bin/stty", {args: stty_args}).outputSync();

    if (!res.success) {
        console.log(String.fromCharCode.apply(null, res.stderr));
        throw("stty failed");
    }

    return Deno.openSync(dev_file, {read: true, write: true});
}

// return a single byte
async function serial_recv() {
    const buf = new Uint8Array(1);

    while (true) {
        const d = await this.read(buf);

        if (d == 1) {
            let ret = buf[0];
            return ret;
        } else if (d == null) {
            throw("serial port closed");
        }
    }
}

// send an array of bytes
function serial_send(arr) {
    let buf = new Uint8Array(arr);

    while (buf.length) {
        const bytes_written = this.writeSync(buf);
        buf = buf.subarray(bytes_written);
    }
}
```

## Security Configuration

The user must provide the following object with Security configuration. Each security class has a 16-byte key array
and a list of Node IDs that are already bootstrapped for this class.

```javascript
const security = {
    s0: {
        key: [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        nodes: [2]
    },
    s2: {
        0: {
            key: [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
            nodes: [3]
        },
        1: {
            key: [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3],
            nodes: [4]
        },
        2: {
            key: [4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4],
            nodes: [5, 6]
        }
    }
};
```

## Logging

The user provides a callback function for logging. Here is an example with date/time prepended:

```javascript
function log(...msg) {
    if (msg.length == 0) {
        console.log("-".repeat(80))
    } else {
        const d = new Date();
        let date_time_ms = (d.getMonth() + 1).toString().padStart(2, "0");
        date_time_ms += "/" + d.getDate().toString().padStart(2, "0");
        date_time_ms += "/" + d.getFullYear().toString();
        date_time_ms += "  " + d.getHours().toString().padStart(2, "0");
        date_time_ms += ":" + d.getMinutes().toString().padStart(2, "0");
        date_time_ms += ":" + d.getSeconds().toString().padStart(2, "0");
        date_time_ms += "." + d.getMilliseconds().toString().padStart(3, "0");
        console.log(date_time_ms, "   ", ...msg);
    }
}
```

## Controller Initialization

The Z-Wave API is accessed using the `zwave_api` class object.

```javascript
import { zwave_api } from "./zwave-js/zwave_api.js"

const serial = serial_init("/dev/ttyUSB0");
var z = new zwave_api(serial_recv.bind(serial), serial_send.bind(serial), log, security);
await z.init();
```

The `init()` function only does:
- Soft Reset
- Basic configuration
- Query HomeID and list of included NodeIDs

## Adding a Node to Network

To add a node:

```javascript
// non-secure
let success = await z.add_node_to_network();

// S0
let success = await z.add_s0_node_to_network();

// S2 without DSK
let success = await z.add_s2_node_to_network();

// S2 with 2-byte DSK
let success = await z.add_s2_node_to_network(12345);

// S2 with 16-byte DSK
let success = await z.add_s2_node_to_network([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
```

In all these cases there is no "interview". The user is responsible for querying the device capabilities and configuring it.

## Removing a Node from Network

To remove a node:

```javascript
let success = await z.remove_node_from_network(100);
```

## Sending Commands to a Node

To send a command:

```javascript
// no reply
let success = await z.node(100).send.SWITCH_BINARY_SET({value: 1}));

// expect reply
let report = await z.node(100).send.SWITCH_BINARY_GET({value: 1})).recv.SWITCH_BINARY_REPORT();

if (report) {
    console.log(report.value);
}

// access MULTI_CHANNEL endpoint
let report = await z.node(100).send.ep(2).SWITCH_BINARY_GET({value: 1})).recv.SWITCH_BINARY_REPORT();
```

Each command defines an argument object with specific parameter names. See `zwave_cc_basic.js` for the definitions.

## Callbacks

Unsolicited commands can be handles with callbacks:

```javascript
z.node(101).recv.WAKE_UP_NOTIFICATION = () => {console.log("wake up")};
z.node(101).recv.SENSOR_BINARY_REPORT = (report) => {console.log("sensor update:", report?.value)};
z.node(101).application_update = (event) => {console.log("application update event:", event)};
```

## Log Examples

S2 SWITCH_BINARY_GET/SWITCH_BINARY_REPORT:

```
02/25/2024  21:18:28.890     BRIDGE_NODE_SEND node:6 | SECURITY_NONCE_GET
02/25/2024  21:18:28.890        TX REQ 01 0e 00 a9 01 06 02 98 40 25 00 00 00 00 0d ad
02/25/2024  21:18:28.896        RX ACK 06
02/25/2024  21:18:28.897        RX RES 01 04 01 a9 01
02/25/2024  21:18:28.897        TX ACK 06
02/25/2024  21:18:28.911        RX REQ 01 05 00 a9 0d 00
02/25/2024  21:18:28.911        TX ACK 06
02/25/2024  21:18:28.912     OK tx_status:0
--------------------------------------------------------------------------------
02/25/2024  21:18:28.927        RX REQ 01 13 00 a8 00 01 06 0a 98 80 52 1a ef 73 7a 80 32 00 00 a8
02/25/2024  21:18:28.927        TX ACK 06
02/25/2024  21:18:28.927     BRIDGE_COMMAND_HANDLER node:6 | SECURITY_NONCE_REPORT nonce: 52 1a ef 73 7a 80 32 00
--------------------------------------------------------------------------------
02/25/2024  21:18:28.929     BRIDGE_NODE_SEND node:6 | SECURITY_MESSAGE_ENCAPSULATION | MULTI_CHANNEL_CMD_ENCAP epid:5 | SWITCH_BINARY_GET
02/25/2024  21:18:28.929        TX REQ 01 26 00 a9 01 06 1a 98 81 5b 79 7d 67 cc 63 47 80 c7 30 85 5c da 6f a4 52 80 e6 39 94 95 d6 86 22 25 00 00 00 00 0e 4e
02/25/2024  21:18:28.937        RX ACK 06
02/25/2024  21:18:28.938        RX RES 01 04 01 a9 01
02/25/2024  21:18:28.938        TX ACK 06
02/25/2024  21:18:28.955        RX REQ 01 05 00 a9 0e 00
02/25/2024  21:18:28.955        TX ACK 06
02/25/2024  21:18:28.955     OK tx_status:0
--------------------------------------------------------------------------------
02/25/2024  21:18:28.969      RX REQ 01 0b 00 a8 00 01 06 02 98 40 00 a8
02/25/2024  21:18:28.969        TX ACK 06
02/25/2024  21:18:28.969     BRIDGE_COMMAND_HANDLER node:6 | SECURITY_NONCE_GET
--------------------------------------------------------------------------------
02/25/2024  21:18:28.969     BRIDGE_NODE_SEND node:6 | SECURITY_NONCE_REPORT nonce: 02 62 a0 fe b5 1e 99 99
02/25/2024  21:18:28.970        TX REQ 01 16 00 a9 01 06 0a 98 80 02 62 a0 fe b5 1e 99 99 25 00 00 00 00 0f ea
02/25/2024  21:18:28.976        RX ACK 06
02/25/2024  21:18:28.978        RX RES 01 04 01 a9 01
02/25/2024  21:18:28.978        TX ACK 06
02/25/2024  21:18:28.991        RX REQ 01 05 00 a9 0f 00
02/25/2024  21:18:28.991        TX ACK 06
02/25/2024  21:18:28.991     OK tx_status:0
--------------------------------------------------------------------------------
02/25/2024  21:18:29.015        RX REQ 01 24 00 a8 00 01 06 1b 98 81 ab 45 fa c1 e4 b1 2b 46 de 12 6e 5f 16 47 18 65 02 d6 e7 a7 3a 83 c3 20 18 00 a8
02/25/2024  21:18:29.015        TX ACK 06
02/25/2024  21:18:29.016     BRIDGE_COMMAND_HANDLER node:6 | SECURITY_MESSAGE_ENCAPSULATION | MULTI_CHANNEL_CMD_ENCAP epid:5 | SWITCH_BINARY_REPORT value:0
--------------------------------------------------------------------------------
```

S2 CONFIGURATION_GET/CONFIGURATION_REPORT:

```
02/25/2024  21:21:52.343     BRIDGE_NODE_SEND node:55 | SECURITY_2_MESSAGE_ENCAPSULATION | CONFIGURATION_GET param:2
02/25/2024  21:21:52.344        TX REQ 01 1b 00 a9 01 37 0f 9f 03 de 00 4d 7c 7e dc 2d f5 af 46 85 f5 ca 25 00 00 00 00 10 1b
02/25/2024  21:21:52.351        RX ACK 06
02/25/2024  21:21:52.352        RX RES 01 04 01 a9 01
02/25/2024  21:21:52.353        TX ACK 06
02/25/2024  21:21:52.363        RX REQ 01 05 00 a9 10 00
02/25/2024  21:21:52.364        TX ACK 06
02/25/2024  21:21:52.364     OK tx_status:0
--------------------------------------------------------------------------------
02/25/2024  21:21:52.378      RX REQ 01 1a 00 a8 00 01 37 11 9f 03 50 00 72 0c a6 92 d7 f5 e9 47 16 3d c9 11 fd 00 a6
02/25/2024  21:21:52.379        TX ACK 06
02/25/2024  21:21:52.380     BRIDGE_COMMAND_HANDLER node:55 | SECURITY_2_MESSAGE_ENCAPSULATION | CONFIGURATION_REPORT param:2 size:1 value:10
--------------------------------------------------------------------------------
```



