# Overview

This module is a minimalist implementation of the Z-Wave API in Javascript to control a simple home network.
I wanted to use Deno instead of Node.js, but the [full-featured implementation](https://github.com/zwave-js),
does not run on Deno, plus it is just so overcomplicated - 128 npm modules for 60MB!

Currently this module only supports the command classes that I need in my network. More classes can be added with the help
of the public [specification](https://www.silabs.com/wireless/z-wave/specification) docs, although I should probably split
those into separate modules eventually. Also for now only S0 security is supported.
S0 seems appropriate for what I need, but I decided to work on S2 for the sake of completeness.
So far I believe I have all the building blocks implemented.

Main features:
 - Single ES module with no external dependencies
 - Uses SubtleCrypto API for encryption
 - Limited set of API and device commands
 - S0 security only

API commands supported:
 - Soft Reset
 - Set Default (erase network)
 - API Setup (Set TX Status Report, Set NodeID Base Type)
 - Get Init Data (get list of nodes)
 - Get Network IDs from Memory (get API module node ID)
 - Add Node to Network (including S0 inclusion)
 - Remove Specific Node From Network
 - Is Node Failed
 - Remove Failed Node
 - Application Update
 - Bridge Controller Node Send Data
 - Bridge Command Handler

Device command classes supported:
 - Switch Binary
 - Sensor Binary
 - Multi Channel
 - Configuration
 - Notification
 - Battery
 - Wake Up
 - Security (S0)

Running on Ubuntu Linux / Deno 1.36.1 using this hardware:
 - Aeotec Z-Stick 7
 - Fibaro Smart Implant (S0 included)
 - Homeseer HS-PA100+ Plug-In Switch
 - Honeywell UltraPro Z-Wave Plus Smart Light Switch
 - Ecolink PIRZWAVE2.5 Z-Wave Plus Motion Sensor
 - GE Enbrighten Z-Wave Plus Smart Outlet Receptacle
