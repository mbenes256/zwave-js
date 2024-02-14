import {pack_fmt, unpack_fmt, print_fmt} from "./zwave_utils.js"
import {zwave_cc_basic} from "./zwave_cc_basic.js"
import {zwave_cc_security} from "./zwave_cc_security.js"

/*
 * command class definitions
 *
 * zwave_cc properties:
 *   <class_name>: class definition object
 *
 * class definition properties:
 *   id: <class id as number>
 *   init(node): optional function that initializes a node with structures used by the class
 *   inclusion(node): optional function to run security inclusion flow
 *   emcapsulate(cmd): optional function that encapsulates command according to the class
 *   cmd: command dictionary
 *
 * command dictionary properties:
 *   <COMMAND_NAME>: command definition object
 *
 * command definition object properties:
 *   id: <command id as number>
 *   encode_fmt: format definition object to encode commands for sending
 *   decode_fmt: format definition object to decode received commands
 *   encode(cmd): function that encodes complex commands, takes command object as argument
 *   decode(cmd): function that decodes complex commands, takes command object as argument
 *
 * format definition object:
 *   <param_name>: number of bytes consumed by parameter
 *      - 0 means variable length (use length of parameter for send, fill remainder of pld for receive)
 *      - trim or pad length for send
 *   _<param_name>: parameter is not printed in msg
 *
 * command object properties:
 *   node: zwave_node object
 *   id: 2-byte array [<cc_id>, <cmd_id>]
 *   msg: array of values to print to log (append by encode() and decode())
 *   pld: encoded payload as array of byte numbers (generate in encode(), consume in decode())
 *   args: object defining command parameters (consume in encode(), generate in decode())
 *   epid: multi-channel endpoint id or undefined
 *   security: "s0" or undefined
 */

export var zwave_cc = {}

Object.assign(zwave_cc, zwave_cc_basic);
Object.assign(zwave_cc, zwave_cc_security);

// post-process all classes
zwave_cc._cc_id_map = new Map();
zwave_cc._cmd_name_map = new Map();

// loop through classes
for (let [cc_name, cc_def] of Object.entries(zwave_cc)) {
    if (cc_def.id != undefined) {
	zwave_cc._cc_id_map.set(cc_def.id, cc_def);
	cc_def.name = cc_name;
	cc_def._cmd_id_map = new Map();

	// loop through commands
	for (let [cmd_name, cmd_def] of Object.entries(cc_def.cmd)) {
	    if (cmd_def.id != undefined) {
		cc_def._cmd_id_map.set(cmd_def.id, cmd_def);
		cmd_def.name = cmd_name;
		cmd_def.cc_id = cc_def.id;
		zwave_cc._cmd_name_map.set(cmd_name, cmd_def);

		// convert fmt to encode/decode
		if (cmd_def.encode_fmt) {
		    const fmt = cmd_def.encode_fmt;
		    cmd_def.encode = (cmd) => {
			cmd.pld = pack_fmt(cmd.args, fmt);
			cmd.msg.push(...print_fmt(cmd.args, fmt));
		    }
		}

		if (cmd_def.decode_fmt) {
		    const fmt_arr = [cmd_def.decode_fmt].flat();
		    cmd_def.decode = (cmd) => {
			for (let fmt of fmt_arr) {
			    cmd.args = unpack_fmt(cmd.pld, fmt);
			    if (cmd.args) {
				cmd.msg.push(...print_fmt(cmd.args, fmt));
				return;
			    }
			}
		    }
		}
	    }
	}
    }
}
