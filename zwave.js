/******************************************************************************
 *     generic utils                                                          *
 ******************************************************************************/

export async function sleep(ms) {
    await new Promise((resolve) => {
        setTimeout(() => resolve(), ms);
    });
}

function obj_val_key(obj, val) {
    for (let e of Object.entries(obj)) {
	if (e[1] == val) {
	    return e[0];
	}
    }

    return obj._default;
}

function get_bit_list(arr, index = 0, val = 1) {
    const len = arr.length;
    const ret = [];

    for (let i = 0; i < len; ++i) {
	let b = arr[i];
	for (let bit = 0; bit < 8; ++bit) {
	    if ((b & 1) == 1) {
		ret.push(index);
	    }
	    ++index;
	    b >>= 1;
	}
    }

    return ret;
}

function hex_bytes(arr) {
    return arr.map((e) => (e & 0xff).toString(16).padStart(2, "0")).join(" ");
}

export class timeout {
    constructor(func, ms) {
	this.func = func;
	this.timeout = setTimeout(this.trigger.bind(this), ms);
    }

    trigger() {
	delete this.timeout;
	this.func();
    }

    cancel() {
	if (this.timeout) {
	    clearTimeout(this.timeout);
	    delete this.timeout;
	}
    }
}

class async_mutex {
    constructor() {
	this.resolve_queue = [];
    }

    async lock() {
	await new Promise((resolve) => {
	    this.resolve_queue.push(resolve);

	    if (this.resolve_queue.length == 1) {
		// nobody is holding the mutex
		resolve();
	    }
	});
    }

    unlock() {
	// notify we re no longer holding the mutex
	this.resolve_queue.shift();

	if (this.resolve_queue.length > 0) {
	    // allow the next requestor to lock
	    this.resolve_queue[0]();
	}
    }
}

function rand(bytes) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return Array.from(buf);
}

/******************************************************************************
 *     AES utils                                                              *
 ******************************************************************************/

async function aes_key_gen(raw) {
    raw = new Uint8Array(raw);
    return await crypto.subtle.importKey("raw", raw, "AES-CBC", false, ["encrypt"]);
}

export async function aes_ecb(key, vec) {
    const plaintext = new Uint8Array(vec);
    const zero_iv = new Uint8Array(16);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name: "AES-CBC", iv: zero_iv}, key, plaintext));

    for (let i = 0; i < 16; ++i) {
	vec[i] = ciphertext[i];
    }

    return vec;
}

function aes_xor(dst, dst_offset, src, src_offset, max_length = 16) {
    const length = Math.min(dst.length - dst_offset, src.length - src_offset, max_length);

    for (let i = 0; i < length; ++i) {
	dst[i + dst_offset] ^= src[i + src_offset];
    }
}

async function s0_key_gen(network_key_raw) {
    const network_key = await aes_key_gen(network_key_raw);
    const auth_key_raw = await aes_ecb(network_key, Array(16).fill(0x55));
    const enc_key_raw = await aes_ecb(network_key, Array(16).fill(0xaa));

    return {auth: await aes_key_gen(auth_key_raw), enc:  await aes_key_gen(enc_key_raw)}
}

/******************************************************************************
 *     zwave                                                                  *
 ******************************************************************************/

export class zwave {
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
	REMOVE_FAILED_NODE:			0x61,
	IS_NODE_FAILED:				0x62,
	BRIDGE_COMMAND_HANDLER:			0xa8,
	BRIDGE_NODE_SEND:			0xa9,

	// unused
	GET_LIBRARY:	 			0xbd,
	SEND_NOP: 				0xe9,
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
	this.s0_temp_key = await s0_key_gen(Array(16).fill(0));

	// start receive loop in backdround
	this.recv_loop();

	// initialization sequence
	this.send_ack_nak(zwave.frame_start.NAK);
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

	    if ([zwave.frame_start.ACK, zwave.frame_start.NAK, zwave.frame_start.CAN].includes(frame_start)) {
		this.recv_ack_nak_can_or_timeout(frame_start);
	    } else if (frame_start == zwave.frame_start.SOF) {
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
		const type_str = obj_val_key(zwave.data_frame_type, type);
		let frame_str = hex_bytes(recv_frame);
		this.log_func("\tRX", type_str, frame_str);

		if (checksum == expected_checksum) {
		    if ([zwave.data_frame_type.REQ, zwave.data_frame_type.RES].includes(type)) {
			this.send_ack_nak(zwave.frame_start.ACK);
			await this.recv_data_frame(type, recv_frame[3], recv_frame.slice(4, len + 1));
		    } else {
			this.log_func("\tRX ERROR bad type");
		    }
		} else {
		    this.log_func("\tRX ERROR bad checksum");
		    this.send_ack_nak(zwave.frame_start.NAK);
		}
	    } else {
		this.log_func("\tRX ERROR unexpected byte", hex_bytes([frame_start]));
	    }
	}
    }

    recv_ack_nak_can_or_timeout(frame_start) {
	if (frame_start) {
	    // not timeout
	    this.log_func("\tRX", obj_val_key(zwave.frame_start, frame_start), hex_bytes([frame_start]));
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
	    if (cmd.onres && (type == zwave.data_frame_type.RES) && (cmd_id == cmd.id)) {
		cmd.onres(pld);
		delete cmd.onres;
		return;
	    } else if (cmd.onreq && (type == zwave.data_frame_type.REQ) &&
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

	if (type == zwave.data_frame_type.REQ) {
	    // unsolicited
	    if (cmd_id == zwave.api_cmd.BRIDGE_COMMAND_HANDLER) {
		await this.recv_bridge_command_handler(pld);
	    } else if (cmd_id == zwave.api_cmd.APPLICATION_UPDATE) {
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
	const type_str = obj_val_key(zwave.data_frame_type, type);
	const args_flat = args.flat(10);
	const len = args_flat.length + 2;
	let checksum = 0xff ^ type ^ len;
	args_flat.forEach((d) => {checksum ^= d});

	for (let n = 0; n < 3; ++n) {
	    let ack_timeout;

	    const ack = await new Promise((resolve) => {
		this.send_data_frame_resolve = resolve;
		ack_timeout = new timeout(this.recv_ack_nak_can_or_timeout.bind(this, null), 1600);
		const frame_str = this.send_frame(zwave.frame_start.SOF, len, type, args_flat, checksum);
		this.log_func("\tTX", type_str, frame_str + ((n > 0) ? (" (retry #" + n + ")") : ""));
	    });

	    ack_timeout.cancel();

	    if (ack == zwave.frame_start.ACK) {
		return true;
	    }

	    // backoff delay before retry
	    await sleep(100 + (n * 1000));
	}

	return false;
    }

    send_ack_nak(frame_start) {
	this.log_func("\tTX", obj_val_key(zwave.frame_start, frame_start), this.send_frame(frame_start));
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
	this.log_func(obj_val_key(zwave.api_cmd, cmd.id), ...(cmd.msg ?? []));
	this.unsolicited_mutex.unlock();

	// send command
	const cmd_promise = new Promise((resolve) => {cmd.resolve = resolve});
	const sent_ok = await this.send_data_frame(zwave.data_frame_type.REQ, cmd.id, ...(cmd.pld ?? []));;
	let cmd_ok = false;

	if (!sent_ok) {
	    this.api_cmd_end(false, "API command not ACKed");
	} else if (!cmd.onres && !cmd.onreq) {
	    this.api_cmd_end(true);
	    cmd_ok = true;
	} else {
	    // wait for completion or timeout
	    const cmd_timeout = new timeout(this.api_cmd_end.bind(this, false, "timeout"), 1000 * (cmd.timeout ?? 1));
	    cmd_ok = await cmd_promise;
	    cmd_timeout.cancel();
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
	return this.nodeid_16bit ? [(nodeid >> 8) & 0xff, nodeid & 0xff] : [nodeid & 0xff];
    }

    // API commands
    async soft_reset() {
	return await this.send_api_cmd({
	    timeout: 20,
	    id: zwave.api_cmd.SOFT_RESET,
	    req_id: zwave.api_cmd.API_STARTED,
	    onreq: (pld) => {
		this.api_cmd_end(true, "API started!");
	    }
	});
    }

    async set_default() {
	return await this.send_api_cmd({
	    id: zwave.api_cmd.SET_DEFAULT,
	    pld: [],
	    onreq: (pld) => {
		this.api_cmd_end(true, "Controller in default state!");
	    }
	});
    }

    async get_network_ids() {
	return await this.send_api_cmd({
	    id: zwave.api_cmd.GET_NETWORK_IDS,
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
	    id: zwave.api_cmd.GET_INIT_DATA,
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
	    id: zwave.api_cmd.API_SETUP,
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
	    id: zwave.api_cmd.API_SETUP,
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
	    id: zwave.api_cmd.ADD_NODE_TO_NETWORK,
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
	    id: zwave.api_cmd.ADD_NODE_TO_NETWORK,
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
	    id: zwave.api_cmd.ADD_NODE_TO_NETWORK,
	    pld: [0xc5, 0 /* fake session ID */]
	});

	if (start_ok && stop_ok && stop_again_ok && (nodeid > 0)) {
	    return nodeid;
	}

	return false;
    }

    async remove_node_from_network(nodeid) {
	const cmd_id = nodeid ? zwave.api_cmd.REMOVE_SPECIFIC_NODE_FROM_NETWORK : zwave.api_cmd.REMOVE_NODE_FROM_NETWORK;

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
	    id: zwave.api_cmd.IS_NODE_FAILED,
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
	    id: zwave.api_cmd.REMOVE_FAILED_NODE,
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
	    id: zwave.api_cmd.BRIDGE_NODE_SEND,
	    pld: [this.encode_nodeid(1), this.encode_nodeid(nodeid),
		  cmd_bytes.length, cmd_bytes, this.tx_options, zwave.no_route],
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

    // complex flows
    async add_secure_node_to_network() {
	const nodeid = await this.add_node_to_network();

	if (!nodeid) {
	    return false;
	}

	const node = this.node(nodeid);

	if (await node.security_scheme_get()) {
	   return await node.network_key_set();
	}

	return false;
    }
}

/******************************************************************************
 *     zwave_node                                                             *
 ******************************************************************************/

export class zwave_node {
    static cc = Object.freeze({
	SWITCH_BINARY:		0x25,
	SENSOR_BINARY:		0x30,
	MULTI_CHANNEL:		0x60,
	CONFIGURATION:		0x70,
	NOTIFICATION:		0x71,
	BATTERY:		0x80,
	WAKE_UP:		0x84,
	SECURITY:		0x98
    });

    static cmd = Object.freeze({
	NO_OPERATION:		[0],

	// switch binary
	SWITCH_BINARY_SET:	[zwave_node.cc.SWITCH_BINARY, 0x01],
	SWITCH_BINARY_GET:	[zwave_node.cc.SWITCH_BINARY, 0x02],
	SWITCH_BINARY_REPORT:	[zwave_node.cc.SWITCH_BINARY, 0x03],

	// sensor binary
	SENSOR_BINARY_REPORT:	[zwave_node.cc.SENSOR_BINARY, 0x03],

	// multi channel
	MULTI_CHANNEL_CMD_ENCAP:	[zwave_node.cc.MULTI_CHANNEL, 0x0d],

	// configuration
	CONFIGURATION_SET: 	[zwave_node.cc.CONFIGURATION, 0x04],
	CONFIGURATION_GET: 	[zwave_node.cc.CONFIGURATION, 0x05],
	CONFIGURATION_REPORT: 	[zwave_node.cc.CONFIGURATION, 0x06],

	// notification
	NOTIFICATION_REPORT: 	[zwave_node.cc.NOTIFICATION, 0x05],

	// battery
	BATTERY_GET:		[zwave_node.cc.BATTERY, 0x02],
	BATTERY_REPORT:		[zwave_node.cc.BATTERY, 0x03],

	// wake up
	WAKE_UP_NOTIFICATION: 	[zwave_node.cc.WAKE_UP, 0x07],

	// security
	SECURITY_COMMANDS_SUPPORTED_GET: 		[zwave_node.cc.SECURITY, 0x02],
	SECURITY_COMMANDS_SUPPORTED_REPORT: 		[zwave_node.cc.SECURITY, 0x03],
	SECURITY_SCHEME_GET: 				[zwave_node.cc.SECURITY, 0x04],
	SECURITY_SCHEME_REPORT: 			[zwave_node.cc.SECURITY, 0x05],
	NETWORK_KEY_SET: 				[zwave_node.cc.SECURITY, 0x06],
	NETWORK_KEY_VERIFY: 				[zwave_node.cc.SECURITY, 0x07],
	SECURITY_SCHEME_INHERIT: 			[zwave_node.cc.SECURITY, 0x08],
	SECURITY_NONCE_GET: 				[zwave_node.cc.SECURITY, 0x40],
	SECURITY_NONCE_REPORT:				[zwave_node.cc.SECURITY, 0x80],
	SECURITY_MESSAGE_ENCAPSULATION:			[zwave_node.cc.SECURITY, 0x81],
	SECURITY_MESSAGE_ENCAPSULATION_NONCE_GET:	[zwave_node.cc.SECURITY, 0xC1],

    });

    constructor(z, nodeid, node, epid, s0) {
	this.z = z;
	this.nodeid = nodeid;
	this.node = node ?? this;

	if (!node) {
	    this.node_cmd_mutex = new async_mutex();
	}

	if (epid) {
	    this.epid = epid;
	}

	if (s0) {
	    this.s0_enabled = s0;
	}
    }

    cached_or_new(epid, s0) {
	if (!this.node.cache) {
	    this.node.cache = new Map();
	}

	const cache_id = "" + (epid ? epid : "") + (s0 ? ".s0" : "");
	let ret = this.node.cache.get(cache_id);

	if (!ret) {
	    ret = new zwave_node(this.z, this.nodeid, this.node, epid, s0);
	    this.node.cache.set(cache_id, ret);
	}
	return ret;
    }

    ep(epid) {
	return this.node.cached_or_new(epid, this.s0_enabled);
    }

    get s0() {
	return this.node.cached_or_new(this.epid, true);
    }

    // common
    async send_node_cmd(cmd) {
	// setup
	if (!cmd.msg) {
	    cmd.msg = [];
	}

	cmd.node = this;
	const cmd_id_str = obj_val_key(zwave_node.cmd, cmd.id);
	cmd.msg.unshift(cmd_id_str);
	cmd.error_msg = ["nodeid:" + this.nodeid];

	// special case because this is response command that must bypass mutex
	if (cmd.id == zwave_node.cmd.SECURITY_NONCE_REPORT) {
	    return await this.z.bridge_node_send(cmd);
	}

	// encapsulate as needed
	if (this.epid) {
	    this.multi_channel_encapsulate(cmd);
	    cmd.error_msg.push("ep:" + this.epid);
	}

	cmd.error_msg.push(cmd_id_str);

	if (this.s0_enabled) {
	    if (!await this.s0_encapsulate(cmd)) {
		// cannot call node_cmd_end because node_cmd_current is not valid
		this.log_func("ERROR", ...cmd.error_msg, "no nonce");
		this.log_func();
		return false;
	    }
	}

	// allow only one command at a time
	await this.node.node_cmd_mutex.lock();
	this.node.node_cmd_current = cmd;

	// send
	const cmd_promise = new Promise((resolve) => {cmd.resolve = resolve});
	const sent_ok = await this.z.bridge_node_send(cmd);
	let cmd_ok = false;

	if (!sent_ok) {
	    this.node_cmd_end(false, "send failed");
	} else if (!cmd.report_cmd_id) {
	    this.node_cmd_end(true);
	    cmd_ok = true;
	} else {
	    // wait for completion or timeout
	    const cmd_timeout = new timeout(this.node_cmd_end.bind(this, false, "timeout"), 1000 * (cmd.timeout ?? 1));
	    cmd_ok = await cmd_promise;
	    cmd_timeout.cancel();
	}

	return cmd.retval ?? cmd_ok;
    }

    node_cmd_end(cmd_ok, ...msg) {
	const cmd = this.node.node_cmd_current;

	if (!cmd_ok) {
	    this.log_func("ERROR", ...cmd.error_msg, ...msg);
	    this.log_func();
	}

	cmd.resolve(cmd_ok);
	delete this.node.node_cmd_current;
	this.node.node_cmd_mutex.unlock();
    }

    async s0_encapsulate(cmd) {
	cmd.msg.unshift("SECURITY_MESSAGE_ENCAPSULATION |");

	const key = (cmd.id == zwave_node.cmd.NETWORK_KEY_SET) ? this.z.s0_temp_key : this.z.s0_key;
	const encrypted_pld = [0 /* seq_info */, cmd.id, cmd.pld ?? []].flat(10);
	cmd.id = zwave_node.cmd.SECURITY_MESSAGE_ENCAPSULATION;

	// get nonce
	const receiver_nonce = await this.security_nonce_get();

	if (!receiver_nonce) {
	    return false;
	}

	// encrypt
	const sender_nonce = rand(8);
	const vec = sender_nonce.concat(receiver_nonce); // Initialization Vector

	for (let offset = 0; offset < encrypted_pld.length; offset += 16) {
	    await aes_ecb(key.enc, vec);
	    aes_xor(encrypted_pld, offset, vec, 0);
	}

	// authentication code
	vec.fill(0);
	const auth_data = [sender_nonce, receiver_nonce, cmd.id[1], this.z.nodeid, this.nodeid,
			   encrypted_pld.length, encrypted_pld].flat();
	for (let offset = 0; offset < auth_data.length; offset += 16) {
	    aes_xor(vec, 0, auth_data, offset);
	    await aes_ecb(key.auth, vec);
	}

	const mac = vec.slice(0, 8);

	// encapsulate
	cmd.pld = [sender_nonce, encrypted_pld, receiver_nonce[0], mac];
	return true;
    }

    multi_channel_encapsulate(cmd) {
	cmd.msg.unshift("MULTI_CHANNEL_CMD_ENCAP ep:" + this.epid, "|");
	cmd.pld = [0, this.epid, cmd.id, cmd.pld ?? []];
	cmd.id = zwave_node.cmd.MULTI_CHANNEL_CMD_ENCAP;
    }

    // send commands
    async no_operation() {
	return await this.send_node_cmd({
	    id: zwave_node.cmd.NO_OPERATION
	});
    }

    async switch_binary_set(val) {
	return await this.send_node_cmd({
	    msg: ["value:" + val],
	    id: zwave_node.cmd.SWITCH_BINARY_SET,
	    pld: [val]
	});
    }

    async switch_binary_get() {
	return await this.send_node_cmd({
	    id: zwave_node.cmd.SWITCH_BINARY_GET,
	    report_cmd_id: zwave_node.cmd.SWITCH_BINARY_REPORT,
	    retval: -1
	});
    }

    async security_scheme_get() {
	return await this.send_node_cmd({
	    id: zwave_node.cmd.SECURITY_SCHEME_GET,
	    report_cmd_id: zwave_node.cmd.SECURITY_SCHEME_REPORT,
	    pld: [0]
	});
    }

    async security_nonce_get() {
	return await this.node.send_node_cmd({
	    id: zwave_node.cmd.SECURITY_NONCE_GET,
	    report_cmd_id: zwave_node.cmd.SECURITY_NONCE_REPORT,
	});
    }

    async network_key_set() {
	return await this.node.s0.send_node_cmd({
	    id: zwave_node.cmd.NETWORK_KEY_SET,
	    report_cmd_id: zwave_node.cmd.NETWORK_KEY_VERIFY,
	    pld: this.z.s0_network_key
	});
    }

    async configuration_set(param, size, val) {
	param &= 0xff;
	if (![1, 2, 4].includes(size)) {
	    throw("unsupported size: " + size);
	}

	const val_buf = new Uint8Array(size);
	const dv = new DataView(val_buf.buffer);

	if (size == 1) {
	    dv.setInt8(0, val);
	} else if (size == 2) {
	    dv.setInt16(0, val);
	} else {
	    dv.setInt32(0, val);
	}

	return await this.send_node_cmd({
	    msg: ["param:" + param + " size:" + size + " value:" + val],
	    id: zwave_node.cmd.CONFIGURATION_SET,
	    pld: [param, size, Array.from(val_buf)]
	});
    }

    async configuration_get(param) {
	param &= 0xff;
	return await this.send_node_cmd({
	    msg: ["param:" + param],
	    id: zwave_node.cmd.CONFIGURATION_GET,
	    report_cmd_id: zwave_node.cmd.CONFIGURATION_REPORT,
	    pld: [param],
	    retval: -1
	});
    }

    async battery_get() {
	return await this.send_node_cmd({
	    id: zwave_node.cmd.BATTERY_GET,
	    report_cmd_id: zwave_node.cmd.BATTERY_REPORT,
	    retval: -1
	});
    }

    // receive handlers
    async recv_cmd(cmd) {
	// replace ID to one of the predefined IDs so it can be matched
	for (let e of Object.entries(zwave_node.cmd)) {
	    if ((e[1][0] == cmd.id[0]) && (e[1][1] == cmd.id[1])) {
		cmd.id = e[1];
		cmd.msg.push(e[0]);
	    }
	}

	// dispatch
	if (cmd.id == zwave_node.cmd.MULTI_CHANNEL_CMD_ENCAP) {
	    await this.recv_multi_channel_cmd_encap(cmd);
	    return;
	} else if (cmd.id == zwave_node.cmd.SECURITY_MESSAGE_ENCAPSULATION) {
	    await this.recv_security_message_encapsulation(cmd);
	    return;
	} else if (cmd.id == this.node.node_cmd_current?.report_cmd_id) {
	    // responses
	    switch (cmd.id) {
	    case zwave_node.cmd.SWITCH_BINARY_REPORT: this.recv_switch_binary_report(cmd); return;
	    case zwave_node.cmd.CONFIGURATION_REPORT: this.recv_configuration_report(cmd); return;
	    case zwave_node.cmd.BATTERY_REPORT: this.recv_battery_report(cmd); return;
	    case zwave_node.cmd.SECURITY_NONCE_REPORT: this.recv_security_nonce_report(cmd); return;
	    case zwave_node.cmd.SECURITY_SCHEME_REPORT: this.recv_security_scheme_report(cmd); return;
	    case zwave_node.cmd.NETWORK_KEY_VERIFY: this.recv_network_key_verify(cmd); return;
	    }
	} else {
	    // unsolicited
	    switch (cmd.id) {
	    case zwave_node.cmd.SENSOR_BINARY_REPORT: this.recv_sensor_binary_report(cmd); return;
	    case zwave_node.cmd.NOTIFICATION_REPORT: this.recv_notification_report(cmd); return;
	    case zwave_node.cmd.WAKE_UP_NOTIFICATION: this.recv_wake_up_notification(cmd); return;
	    case zwave_node.cmd.SECURITY_NONCE_GET: this.recv_security_nonce_get(cmd); return;
	    }
	}

	cmd.msg.push("unexpected");
    }

    recv_switch_binary_report(cmd) {
	if (cmd.pld.length >= 1) {
	    const val = cmd.pld[0];
	    cmd.msg.push("value:" + val);
	    this.node.node_cmd_current.retval = val;
	    this.node_cmd_end(true);
	} else {
	    cmd.msg.push("bad value");
	    this.node_cmd_end(false, "bad value");
	}
    }

    recv_sensor_binary_report(cmd) {
	let val;

	if (cmd.pld.length >= 1) {
	    val = cmd.pld[0];
	}

	cmd.msg.push("value:" + val);

	if (this.sensor_binary_report) {
	    this.sensor_binary_report(val);
	}
    }

    recv_security_nonce_report(cmd) {
	if (cmd.pld.length == 8) {
	    const nonce = cmd.pld;
	    cmd.msg.push("nonce: " + hex_bytes(nonce));
	    this.node.node_cmd_current.retval = nonce;
	    this.node_cmd_end(true);
	} else {
	    cmd.msg.push("bad value");
	    this.node_cmd_end(false, "bad value");
	}
    }

    recv_configuration_report(cmd) {
	let val;
	let param;
	let size;

    	if (cmd.pld.length >= 3) {
	    param = cmd.pld[0];
	    size = cmd.pld[1];
	    const dv = new DataView((new Uint8Array(cmd.pld.slice(2))).buffer);

	    if (size <= dv.byteLength) {
		if (size == 1) {
		    val = dv.getInt8(0);
		} else if (size == 2) {
		    val = dv.getInt16(0);
		} else if (size == 4) {
		    val = dv.getInt32(0);
		}
	    }
	}

	if (val != undefined) {
	    cmd.msg.push("param:" + param + " size:" + size + " value:" + val);
	    this.node.node_cmd_current.retval = val;
	    this.node_cmd_end(true);
	} else {
	    cmd.msg.push("bad value");
	    this.node_cmd_end(false, "bad value");
	}
    }

    recv_notification_report(cmd) {
	if (cmd.pld.length < 6) {
	    cmd.msg.push("incorrect length " + cmd.pld.length);
	    return;
	}

	const type = cmd.pld[4];
	const state = cmd.pld[5];

	cmd.msg.push("type:" + type + " state:" + state);

	if (this.notification_report) {
	    this.notification_report(type, state);
	}
    }

    recv_battery_report(cmd) {
	let val;

	if (cmd.pld.length >= 1) {
	    const val = cmd.pld[0];
	    cmd.msg.push("level:" + val);
	    this.node.node_cmd_current.retval = val;
	    this.node_cmd_end(true);
	} else {
	    cmd.msg.push("bad value");
	    this.node_cmd_end(false, "bad value");
	}
    }

    recv_wake_up_notification(cmd) {
	if (this.wake_up) {
	    this.wake_up();
	}
    }

    recv_security_nonce_get(cmd) {
	if (cmd.pld.length != 0) {
	    cmd.msg.push("incorrect length");
	    return;
	}

	if (!this.nonce) {
	    this.nonce = Array(256);
	    this.nonce_id = 0;
	}

	const nonce_id = (this.nonce_id + 1) % 256;
	const nonce = rand(8);
	nonce[0] = nonce_id;
	this.nonce[nonce_id] = nonce;
	this.nonce_id = nonce_id;

	// disable after 3 seconds
	setTimeout(() => {nonce.length = 0}, 3000);

	this.node.send_node_cmd({
	    msg: ["nonce: " + hex_bytes(nonce)],
	    id: zwave_node.cmd.SECURITY_NONCE_REPORT,
	    pld: nonce
	});
    }

    recv_security_scheme_report(cmd) {
	this.node_cmd_end((cmd.pld.length == 1) && (cmd.pld[0] == 0));
    }

    recv_network_key_verify(cmd) {
	this.node_cmd_end(cmd.pld.length == 0);
    }

    async recv_security_message_encapsulation(cmd) {
	const encrypted_pld_len = cmd.pld.length - 17; // IV, MAC, receiver nonce identifier not included

	if (encrypted_pld_len < 3) {
	    cmd.msg.push("incorrect length");
	    return;
	}

	// extract fields
	const sender_nonce = cmd.pld.slice(0, 8);
	const receiver_nonce_id_offset = 8 + encrypted_pld_len;
	const encrypted_pld = cmd.pld.slice(8, receiver_nonce_id_offset);
	const receiver_nonce_id = cmd.pld[receiver_nonce_id_offset];
	const mac = cmd.pld.slice(receiver_nonce_id_offset + 1);

	// receiver nonce
	const receiver_nonce = this.node?.nonce[receiver_nonce_id];

	if (!receiver_nonce) {
	    cmd.msg.push("no receiver nonce:" + receiver_nonce_id);
	    return;
	}

	delete this.node.nonce[receiver_nonce_id];

	if (receiver_nonce.length < 8) {
	    cmd.msg.push("receiver nonce expired");
	    return;
	}

	// authentication code check
	const key = this.z.s0_key;
	let vec = Array(16).fill(0);
	const auth_data = [sender_nonce, receiver_nonce, cmd.id[1], this.nodeid, this.z.nodeid,
			   encrypted_pld_len, encrypted_pld].flat();

	for (let offset = 0; offset < auth_data.length; offset += 16) {
	    aes_xor(vec, 0, auth_data, offset);
	    await aes_ecb(key.auth, vec);
	}

	for (let i = 0; i < 8; ++i) {
	    if (vec[i] != mac[i]) {
		cmd.msg.push("incorrect MAC");
		//return;
	    }
	}

	// decrypt
	vec = sender_nonce.concat(receiver_nonce); // Initialization Vector

	for (let offset = 0; offset < encrypted_pld.length; offset += 16) {
	    await aes_ecb(key.enc, vec);
	    aes_xor(encrypted_pld, offset, vec, 0);
	}

	// dispatch encapsulated cmd
	const seq_info = encrypted_pld[0];

	if (seq_info != 0) {
	    cmd.msg.push("unexpected sequence byte:" + seq_info);
	    return;
	}

	cmd.id = encrypted_pld.slice(1, 3);
	cmd.pld = encrypted_pld.slice(3);

	cmd.msg.push("|");
	await this.s0.recv_cmd(cmd);
    }

    async recv_multi_channel_cmd_encap(cmd) {
	if (cmd.pld.length < 4) {
	    cmd.msg.push("incorrect length");
	    return;
	}

	const epid = cmd.pld[0];
	cmd.id = cmd.pld.slice(2, 4);
	cmd.pld = cmd.pld.slice(4);
	cmd.msg.push("ep:" + epid, "|");

	await this.ep(epid).recv_cmd(cmd);
    }
}
