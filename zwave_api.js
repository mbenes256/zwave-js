import {async_mutex, sleep, obj_val_key, get_bit_list, hex_bytes, encode_msb_first} from "./zwave_utils.js"
import {zwave_node} from "./zwave_node.js"
import {zwave_cc} from "./zwave_cc.js"
import {s0_key_gen, aes_block} from "./zwave_cc_security.js"

/*
 * This class handles sending and receiving API commands to Z-Wave chip
 */

export class zwave_api {
    // first byte in frame
    static frame_start = Object.freeze({
	ACK: 0x06,
	NAK: 0x15,
	CAN: 0x18,
	SOF: 0x01,
	_default: "INV"
    });

    // data frame type (byte 2)
    static data_frame_type = Object.freeze({
	REQ: 0,
	RES: 1,
	_default: "INV"
    });

    // commands
    static api_cmd = Object.freeze({
	GET_INIT_DATA:				0x02,
	SOFT_RESET: 				0x08,
	API_STARTED: 				0x0a,
	API_SETUP: 				0x0b,
	GET_NETWORK_IDS: 			0x20,
	REMOVE_SPECIFIC_NODE_FROM_NETWORK:	0x3f,
	SET_DEFAULT:				0x42,
	APPLICATION_UPDATE:			0x49,
	ADD_NODE_TO_NETWORK:			0x4a,
	REMOVE_NODE_FROM_NETWORK: 		0x4b,
	REQUEST_NODE_INFORMATION:		0x60,
	REMOVE_FAILED_NODE:			0x61,
	IS_NODE_FAILED:				0x62,
	BRIDGE_COMMAND_HANDLER:			0xa8,
	BRIDGE_NODE_SEND:			0xa9
    });

    static no_route = [0, 0, 0, 0];

    /******************************************************************************
     *     initialization                                                         *
     ******************************************************************************/

    // recv_func      ... async function that returns 1 byte received from serial port as Number
    // send_func      ... function that takes Array of Numbers as bytes to send to serial port
    // log_func       ... function to log low-level send/receive command info
    // s0_network_key ... Array of 16 numbers

    constructor(recv_func, send_func, log_func, s0_network_key) {
	this.send_func = send_func;
	this.recv_func = recv_func;
	this.log_func = log_func;
	this.s0_network_key = s0_network_key;
	this.tx_options = 0x25; // ACK + AUTO_ROUTE + EXPLORE
	this.unsolicited_mutex = new async_mutex();
	this.api_cmd_mutex = new async_mutex();
	this.api_cmd_session_id = 1; // counter to increment for each new session
	this.nodes = new Map();
    }

    async init() {
	this.s0_key = await s0_key_gen(this.s0_network_key);
	this.s0_temp_key = await s0_key_gen(aes_block(0));

	// start receive loop in backdround
	this.recv_loop();

	// initialization sequence
	this.send_ack_nak(zwave_api.frame_start.NAK);
	await this.soft_reset();
	await this.set_tx_status_report(false);
	await this.set_nodeid_base_type(false);
	await this.get_network_ids();
	await this.get_init_data();
    }

    node(nodeid) {
	let node = this.nodes.get(nodeid);

	if (!node) {
	    node = new zwave_node(this, nodeid);
	    this.nodes.set(nodeid, node);
	}

	return node;
    }

    /******************************************************************************
     *     receive pipeline                                                       *
     ******************************************************************************/

    async recv_loop() {
	while (true) {
	    const frame_start = await this.recv_func();

	    if ([zwave_api.frame_start.ACK, zwave_api.frame_start.NAK,
		 zwave_api.frame_start.CAN].includes(frame_start)) {
		this.recv_ack_nak_can_or_timeout(frame_start);
	    } else if (frame_start == zwave_api.frame_start.SOF) {
		const len = await this.recv_func();
		const type = await this.recv_func();
		const recv_frame = [frame_start, len, type];
		let expected_checksum = 0xff ^ type ^ len;

		for (let i = 2; i < len; ++i) {
		    const byte = await this.recv_func();
		    recv_frame.push(byte);
		    expected_checksum ^= byte;
		}

		const checksum = await this.recv_func();
		const type_str = obj_val_key(zwave_api.data_frame_type, type);
		let frame_str = hex_bytes(recv_frame);
		this.log_func("\tRX", type_str, frame_str);

		if (checksum == expected_checksum) {
		    if ([zwave_api.data_frame_type.REQ, zwave_api.data_frame_type.RES].includes(type)) {
			this.send_ack_nak(zwave_api.frame_start.ACK);
			await this.recv_data_frame(type, recv_frame[3], recv_frame.slice(4, len + 1));
		    } else {
			this.log_func("\tRX ERROR bad type");
		    }
		} else {
		    this.log_func("\tRX ERROR bad checksum");
		    this.send_ack_nak(zwave_api.frame_start.NAK);
		}
	    } else {
		this.log_func("\tRX ERROR unexpected byte", hex_bytes([frame_start]));
	    }
	}
    }

    recv_ack_nak_can_or_timeout(frame_start) {
	if (frame_start) {
	    // not timeout
	    this.log_func("\tRX", obj_val_key(zwave_api.frame_start, frame_start), hex_bytes([frame_start]));
	}

	if (this.send_data_frame_resolve) {
	    this.send_data_frame_resolve(frame_start);
	    delete this.send_data_frame_resolve;
	}
    }

    async recv_data_frame(type, cmd_id, pld) {
	// pld starts with first byte after cmd_id
	const cmd = this.api_cmd_current;

	if (cmd) {
	    // pass to command callbacks
	    if (cmd.onres && (type == zwave_api.data_frame_type.RES) && (cmd_id == cmd.id)) {
		cmd.onres(pld);
		delete cmd.onres;
		return;
	    } else if (cmd.onreq && (type == zwave_api.data_frame_type.REQ) &&
		       (cmd_id == cmd.req_id) && (!cmd.session_id || (pld[0] == cmd.session_id))) {
		if (cmd.session_id) {
		    // remove session ID
		    pld.shift();
		}
		cmd.onreq(pld);
		return;
	    }
	}

	// unsolicited
	await this.unsolicited_mutex.lock();

	if (type == zwave_api.data_frame_type.REQ) {
	    // unsolicited
	    if (cmd_id == zwave_api.api_cmd.BRIDGE_COMMAND_HANDLER) {
		await this.recv_bridge_command_handler(pld);
	    } else if (cmd_id == zwave_api.api_cmd.APPLICATION_UPDATE) {
		this.recv_application_update(pld);
	    } else {
		this.log_func("\tRX ERROR unhandled unsolicited Request");
	    }
	} else {
	    this.log_func("\tRX ERROR unexpected Response");
	}
	this.log_func();

	this.unsolicited_mutex.unlock();
    }

    async recv_bridge_command_handler(pld) {
	const msg = "BRIDGE_COMMAND_HANDLER";

	// pld starts with first byte after cmd_id
	if (pld.length < (6 + (this.nodeid_16bit ? 2 : 0))) {
	    this.log_func(msg, "invalid command (too short)");
	    return;
	}

	const len_offset = this.nodeid_16bit ? 5 : 3;
	const cmd_offset = len_offset + 1;
	const len = pld[len_offset];
	const cmd_end = cmd_offset + len;

	if (!((len >= 2) && (cmd_end <= pld.length))) {
	    this.log_func(msg, "invalid command (pld doesn't fit)");
	    return;
	}

	const nodeid = pld[len_offset - 1] + (pld[len_offset - 2] * (this.nodeid_16bit ? 256 : 0));
	const node = this.nodes.get(nodeid);

	if (node) {
	    const cmd = {
		id: pld.slice(cmd_offset, cmd_offset + 2),
		pld: pld.slice(cmd_offset + 2, cmd_end),
		msg: []
	    };

	    try {
		await node.recv_cmd(cmd);
	    } catch (error) {
		console.log(error);
	    }

	    this.log_func(msg, "node:" + node.nodeid, "|", ...cmd.msg);
	} else {
	    this.log_func(msg, "non-existent node:" + nodeid);
	}
    }

    recv_application_update(pld) {
	const msg = "APPLICATION_UPDATE";

	// pld starts with first byte after cmd_id
	if (pld.length < (3 + (this.nodeid_16bit ? 1 : 0))) {
	    this.log_func(msg, "invalid command (too short)");
	    return;
	}

	const event = pld[0];
	const nodeid_lsb_offset = this.nodeid_16bit ? 2 : 1;
	const nodeid = pld[nodeid_lsb_offset] + (pld[nodeid_lsb_offset - 1] * (this.nodeid_16bit ? 256 : 0));
	const node = this.nodes.get(nodeid);

	if (node) {
	    this.log_func(msg, "node:" + node.nodeid, "|", event);

	    if (node.application_update) {
		node.application_update(event);
	    }
	} else {
	    this.log_func(msg, "non-existent node:" + nodeid);
	}
    }

    /******************************************************************************
     *     send pipeline                                                          *
     ******************************************************************************/

    // framing
    send_frame(...args) { // args must be numbers or arrays of numbers (incl. nested)
	args = args.flat(10);
	this.send_func(args);
	return hex_bytes(args);
    }

    async send_data_frame(type, ...args) {
	const type_str = obj_val_key(zwave_api.data_frame_type, type);
	const args_flat = args.flat(10);
	const len = args_flat.length + 2;
	let checksum = 0xff ^ type ^ len;
	args_flat.forEach((d) => {checksum ^= d});

	for (let n = 0; n < 3; ++n) {
	    let ack_timeout;

	    const ack = await new Promise((resolve) => {
		this.send_data_frame_resolve = resolve;
		ack_timeout = setTimeout(this.recv_ack_nak_can_or_timeout.bind(this, null), 1600);
		const frame_str = this.send_frame(zwave_api.frame_start.SOF, len, type, args_flat, checksum);
		this.log_func("\tTX", type_str, frame_str + ((n > 0) ? (" (retry #" + n + ")") : ""));
	    });

	    clearTimeout(ack_timeout);

	    if (ack == zwave_api.frame_start.ACK) {
		return true;
	    }

	    // backoff delay before retry
	    await sleep(100 + (n * 1000));
	}

	return false;
    }

    send_ack_nak(frame_start) {
	this.log_func("\tTX", obj_val_key(zwave_api.frame_start, frame_start), this.send_frame(frame_start));
    }

    // common API command functions
    async send_api_cmd(cmd) {
	await this.api_cmd_mutex.lock();
	this.api_cmd_current = cmd;
	await this.unsolicited_mutex.lock(); // hold off processing until unsolicited handler completes

	if (cmd.onreq && !cmd.req_id) {
	    // uses calbacks - append new sessio_id at the end of the frame
	    ++this.api_cmd_session_id;

	    if (this.api_cmd_session_id >= 256) {
		this.api_cmd_session_id = 1;
	    }

	    cmd.session_id = this.api_cmd_session_id;
	    cmd.pld.push(cmd.session_id);
	    cmd.req_id = cmd.id;
	}

	// print out what is about to happen
	this.log_func(obj_val_key(zwave_api.api_cmd, cmd.id), ...(cmd.msg ?? []));
	this.unsolicited_mutex.unlock();

	// send command
	const cmd_promise = new Promise((resolve) => {cmd.resolve = resolve});
	const sent_ok = await this.send_data_frame(zwave_api.data_frame_type.REQ, cmd.id, ...(cmd.pld ?? []));;
	let cmd_ok = false;

	if (!sent_ok) {
	    this.api_cmd_end(false, "API command not ACKed");
	} else if (!cmd.onres && !cmd.onreq) {
	    this.api_cmd_end(true);
	    cmd_ok = true;
	} else {
	    // wait for completion or timeout
	    const cmd_timeout = setTimeout(this.api_cmd_end.bind(this, false, "timeout"), 1000 * (cmd.timeout ?? 1));
	    cmd_ok = await cmd_promise;
	    clearTimeout(cmd_timeout);
	}

	return cmd_ok;
    }

    api_cmd_end(cmd_ok, ...msg) {
	this.log_func(cmd_ok ? "OK" : "ERROR", ...msg);
	this.log_func();
	this.api_cmd_current.resolve(cmd_ok);
	delete this.api_cmd_current;
	this.api_cmd_mutex.unlock();
    }

    encode_nodeid(nodeid) {
	return encode_msb_first(nodeid, this.nodeid_16bit ? 2 : 1);
    }

    // API commands
    async soft_reset() {
	return await this.send_api_cmd({
	    timeout: 20,
	    id: zwave_api.api_cmd.SOFT_RESET,
	    req_id: zwave_api.api_cmd.API_STARTED,
	    onreq: (pld) => {
		this.api_cmd_end(true, "API started!");
	    }
	});
    }

    async set_default() {
	return await this.send_api_cmd({
	    id: zwave_api.api_cmd.SET_DEFAULT,
	    pld: [],
	    onreq: (pld) => {
		this.api_cmd_end(true, "Controller in default state!");
	    }
	});
    }

    async get_network_ids() {
	return await this.send_api_cmd({
	    id: zwave_api.api_cmd.GET_NETWORK_IDS,
	    pld: [],
	    onres: (pld) => {
		this.home_id = pld.slice(0, 4);
		this.nodeid = pld[4];
		this.api_cmd_end(true, "HomeID: " + hex_bytes(this.home_id), "nodeid:" + this.nodeid);
	    }
	});
    }

    async get_init_data() {
	return await this.send_api_cmd({
	    id: zwave_api.api_cmd.GET_INIT_DATA,
	    onres: (pld) => {
		const node_list_length = pld[2];

		if (node_list_length == (pld.length - 5)) {
		    const node_list = [];
		    for (let nodeid of get_bit_list(pld.slice(3, 3 + node_list_length), 1)) {
			this.node(nodeid);
			node_list.push(nodeid);
		    }
		    this.api_cmd_end(true, "nodes: " + node_list.join(" "));
		} else {
		    this.api_cmd_end(false, "Invalid response");
		}
	    }
	});
    }

    async set_tx_status_report(enable) {
	return await this.send_api_cmd({
	    msg: ["| Set TX Status Report: ", enable ? "enabled" : "disabled"],
	    id: zwave_api.api_cmd.API_SETUP,
	    pld: [0x02, enable ? 1 : 0],
	    onres: (pld) => {
		if ((pld.length == 2) && (pld[1] != 0)) {
		    this.api_cmd_end(true);
		} else {
		    this.api_cmd_end(false, "status:" + pld[1]);
		}
	    }
	});
    }

    async set_nodeid_base_type(enable_16bit) {
	return await this.send_api_cmd({
	    msg: ["| Set NodeID Base Type: ", enable_16bit ? "16-bit" : "8-bit"],
	    id: zwave_api.api_cmd.API_SETUP,
	    pld: [0x80, enable_16bit ? 2 : 1],
	    onres: (pld) => {
		if ((pld.length == 2) && (pld[1] != 0)) {
		    this.nodeid_16bit = enable_16bit;
		    this.api_cmd_end(true);
		} else {
		    this.api_cmd_end(false, "status:" + pld[1]);
		}
	    }
	});
    }

    async add_node_to_network() {
	let nodeid;

	const start_ok = await this.send_api_cmd({
	    timeout: 60,
	    msg: ["Add any node"],
	    id: zwave_api.api_cmd.ADD_NODE_TO_NETWORK,
	    pld: [0xc1],
	    onreq: (pld) => {
		switch (pld[0]) {
		case 0x1: this.log_func("Network Inclusion Started"); break;
		case 0x2: this.log_func("Node found"); break;
		case 0x3: this.log_func("Inclusion ongoing (End Node)"); break;
		case 0x4: this.log_func("Inclusion ongoing (Controller Node)"); break;
		case 0x5:
		    nodeid = pld[1]; // TODO support 16-bit
		    this.api_cmd_end(true, "Inclusion Completed (protocol part) - node:" + nodeid);
		    break;
		default:  this.api_cmd_end(false, "Unexpected status:" + pld[0]);
		}
	    }
	});

	if (nodeid) {
	    // register it
	    this.node(nodeid);
	}

	const stop_ok = await this.send_api_cmd({
	    msg: ["Stop network inclusion"],
	    id: zwave_api.api_cmd.ADD_NODE_TO_NETWORK,
	    pld: [0xc5],
	    onreq: (pld) => {
		if (pld[0] == 0x6) {
		    this.api_cmd_end(true, "Network Inclusion Stopped");
		} else {
		    this.api_cmd_end(false, "Unexpected status:" + pld[0]);
		}
	    }
	});

	// repeat stop but this time no callback expected
	const stop_again_ok = await this.send_api_cmd({
	    msg: ["Stop network inclusion (again)"],
	    id: zwave_api.api_cmd.ADD_NODE_TO_NETWORK,
	    pld: [0xc5, 0 /* fake session ID */]
	});

	if (start_ok && stop_ok && stop_again_ok && (nodeid > 0)) {
	    return nodeid;
	}

	return false;
    }

    async remove_node_from_network(nodeid) {
	const cmd_id = nodeid ? zwave_api.api_cmd.REMOVE_SPECIFIC_NODE_FROM_NETWORK :
	      zwave_api.api_cmd.REMOVE_NODE_FROM_NETWORK;

	const start_ok = await this.send_api_cmd({
	    timeout: 60,
	    msg: ["|", nodeid ? "Remove node:" + nodeid : "Remove any node"],
	    id: cmd_id,
	    pld: nodeid ? [0xc1, nodeid] : [0xc1],
	    onreq: (pld) => {
		switch (pld[0]) {
		case 0x1: this.log_func("Network Exclusion Started"); break;
		case 0x2: this.log_func("Node found"); break;
		case 0x3: this.log_func("Exclusion ongoing (End Node)"); break;
		case 0x4: this.log_func("Exclusion ongoing (Controller Node)"); break;
		case 0x6: this.api_cmd_end(true, "Exclusion completed"); break;
		default:  this.api_cmd_end(false, "Unexpected status:" + pld[0]);
		}
	    }
	});

	// no callback expected on the stop
	const stop_ok = await this.send_api_cmd({
	    msg: ["|", "Stop network exclusion"],
	    id: cmd_id,
	    pld: [0xc5, 0 /* fake session ID */]
	});

	return start_ok && stop_ok;
    }

    async is_node_failed(nodeid) {
	return await this.send_api_cmd({
	    id: zwave_api.api_cmd.IS_NODE_FAILED,
	    pld: [nodeid],
	    onres: (pld) => {
		if (pld[0] < 2) {
		    this.api_cmd_end((pld[0] == 1), "Failed:", (pld[0] == 1) ? "Yes" : "No");
		} else {
		    this.api_cmd_end(false, "Unexpected response:" + pld[0]);
		}
	    }
	});
    }

    async remove_failed_node(nodeid) {
	return await this.send_api_cmd({
	    msg: ["Remove node:" + nodeid],
	    id: zwave_api.api_cmd.REMOVE_FAILED_NODE,
	    pld: [nodeid],
	    onres: (pld) => {
		switch (pld[0]) {
		case 0x0: this.log_func("Failed node remove started"); break;
		case 0x1: this.api_cmd_end(false, "Not primary controller"); break;
		case 0x2: this.api_cmd_end(false, "No callback function"); break;
		case 0x3: this.api_cmd_end(false, "Failed node not found"); break;
		case 0x4: this.api_cmd_end(false, "Failed node remove process busy"); break;
		case 0x5: this.api_cmd_end(false, "Failed node remove fail"); break;
		default:  this.api_cmd_end(false, "Unexpected response:" + pld[0])
		}
	    },
	    onreq: (pld) => {
		switch (pld[0]) {
		case 0x0: this.api_cmd_end(false, "Node OK (not removed)"); break;
		case 0x1: this.api_cmd_end(true, "Failed node removed"); break;
		case 0x2: this.api_cmd_end(false, "Failed node not removed"); break;
		default:  this.api_cmd_end(false, "Unexpected status:" + pld[0]);
		}
	    }
	});
    }

    async bridge_node_send(cmd) {
	const cmd_bytes = [cmd.id, cmd.pld ?? []].flat(10);
	const nodeid = cmd.node.nodeid;

	return await this.send_api_cmd({
	    timeout: 20, // let the controller retry - it is expected to timeout in about 12 seconds
	    msg: ["node:" + nodeid, "|", ...(cmd.msg ?? [])],
	    id: zwave_api.api_cmd.BRIDGE_NODE_SEND,
	    pld: [this.encode_nodeid(1), this.encode_nodeid(nodeid),
		  cmd_bytes.length, cmd_bytes, this.tx_options, zwave_api.no_route],
	    onres: (pld) => {
		if (!((pld.length == 1) && (pld[0] != 0))) {
		    this.api_cmd_end(false, "response:" + pld[0]);
		}
	    },
	    onreq: (pld) => {
		const status = pld[0];
		this.api_cmd_end(status == 0, "tx_status:" + status);
	    }
	});
    }

    async request_node_information(nodeid) {
	return await this.send_api_cmd({
	    id: zwave_api.api_cmd.REQUEST_NODE_INFORMATION,
	    pld: [nodeid],
	    onres: (pld) => {
		if ((pld.length == 1) && (pld[0] != 0)) {
		    this.api_cmd_end(true);
		} else {
		    this.api_cmd_end(false, "status:" + pld[0]);
		}
	    }
	});
    }

    // complex flows
    async add_s0_node_to_network() {
	const nodeid = await this.add_node_to_network();

	if (nodeid) {
	    return await zwave_cc.SECURITY.inclusion(this.node(nodeid));
	}

	return false;
    }
}
