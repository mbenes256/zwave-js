# Overview

This module is a minimalist implementation of a Z-Wave API to control a simple home network using a USB host controller.
Unlike the full-featured Node-based implementation that can be found [here](https://github.com/zwave-js), the goal of this project was
to work in any Javascript runtime with minimal external dependencies for a stable and secure long-term solution with minimal maintenance.

This code is provided in hope that it can be a starting point for similarly-minded enthusiasts. It only implements the Z-Wave commands
I need in my home network. So any users would be expected to add their own commands with the help of the official specification that
can be downloaded [here](https://www.silabs.com/wireless/z-wave/specification).

Main features:
 - Single ES module
 - No external dependencies
 - Uses SubtleCrypto API for encryption
 - Limited set of API and device commands
 - S0 security

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
 - Bridge Controller Node Send Data

Device command classes supported:
 - Switch Binary
 - Sensor Binary
 - Multi Channel
 - Configuration
 - Notification
 - Battery
 - Wake Up
 - Security (S0)

Tested on hardware:
 - Aeotec Z-Stick 7
 - Fibaro Smart Implant (S0 included)
 - Homeseer HS-PA100+ Plug-In Switch
 - Honeywell UltraPro Z-Wave Plus Smart Light Switch
 - Ecolink PIRZWAVE2.5 Z-Wave Plus Motion Sensor
 - GE Enbrighten Z-Wave Plus Smart Outlet Receptacle
