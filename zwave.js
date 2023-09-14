/******************************************************************************
 *     generic utils                                                          *
 ******************************************************************************/

export async function sleep(ms) {
    await new Promise((resolve) => {
        setTimeout(() => resolve(), ms);
    });
}

Object.prototype.get_key = function (val) {
    for (let e of Object.entries(this)) {
	if (e[1] == val) {
	    return e[0];
	}
    }

    return this._default;
}

Array.prototype.get_bit_list = function(index = 0, val = 1) {
    const len = this.length;
    const ret = [];

    for (let i = 0; i < len; ++i) {
	let b = this[i];
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

Array.prototype.to_hex_bytes = function() {
    return this.map((e) => (e & 0xff).toString(16).padStart(2, "0")).join(" ");
}

class timeout {
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

class async_queue {
    constructor() {
	this.queue = [];
    }

    put(item) {
	if (this.get_resolve) {
	    // someone already waiting
	    this.get_resolve(item);
	    delete this.get_resolve;
	} else {
	    this.queue.push(item);
	}
    }

    async get() {
	return await new Promise((resolve) => {
	    if (this.queue.length > 0) {
		// something already in the queue
		resolve(this.queue.shift());
	    } else {
		this.get_resolve = resolve;
	    }
	});
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

function date_time_ms() {
    const d = new Date();
    let str = d.getMonth().toString().padStart(2, "0");
    str += "/" + d.getDate().toString().padStart(2, "0");
    str += "/" + d.getFullYear().toString();
    str += "  " + d.getHours().toString().padStart(2, "0");
    str += ":" + d.getMinutes().toString().padStart(2, "0");
    str += ":" + d.getSeconds().toString().padStart(2, "0");
    str += "." + d.getMilliseconds().toString().padStart(3, "0");
    return str;
}

function log(...msg) {
    console.log(date_time_ms(), "   ", ...msg);
}

function rand(bytes) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return Array.from(buf);
}

/******************************************************************************
 *     AES utils                                                              *
 ******************************************************************************/

const aes_zero = new Uint8Array(16);

async function aes_key_gen(raw) {
    raw = new Uint8Array(raw);
    return await crypto.subtle.importKey("raw", raw, "AES-CTR", false, ["encrypt"]);
}

async function aes_ecb(key, vec) {
    const plaintext = new Uint8Array(vec);
    // pass the plaintext as counter input to encrypt a single block
    const ciphertext = await crypto.subtle.encrypt({name: "AES-CTR", counter: plaintext, length: 64}, key, aes_zero);

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

    return {
	auth: await aes_key_gen(await aes_ecb(network_key, Array(16).fill(0x55))),
	enc:  await aes_key_gen(await aes_ecb(network_key, Array(16).fill(0xaa)))
    }
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

    static node_cc = Object.freeze({
	SWITCH_BINARY:		0x25,
	SECURITY:		0x98
    });

    static node_cmd = Object.freeze({
	NO_OPERATION:		[0],

	// switch binary
	SWITCH_BINARY_SET:	[zwave.node_cc.SWITCH_BINARY, 0x01],
	SWITCH_BINARY_GET:	[zwave.node_cc.SWITCH_BINARY, 0x02],
	SWITCH_BINARY_REPORT:	[zwave.node_cc.SWITCH_BINARY, 0x03],

	// security
	SECURITY_COMMANDS_SUPPORTED_GET: 		[zwave.node_cc.SECURITY, 0x02],
	SECURITY_COMMANDS_SUPPORTED_REPORT: 		[zwave.node_cc.SECURITY, 0x03],
	SECURITY_SCHEME_GET: 				[zwave.node_cc.SECURITY, 0x04],
	SECURITY_SCHEME_REPORT: 			[zwave.node_cc.SECURITY, 0x05],
	NETWORK_KEY_SET: 				[zwave.node_cc.SECURITY, 0x06],
	NETWORK_KEY_VERIFY: 				[zwave.node_cc.SECURITY, 0x07],
	SECURITY_SCHEME_INHERIT: 			[zwave.node_cc.SECURITY, 0x08],
	SECURITY_NONCE_GET: 				[zwave.node_cc.SECURITY, 0x40],
	SECURITY_NONCE_REPORT:				[zwave.node_cc.SECURITY, 0x80],
	SECURITY_MESSAGE_ENCAPSULATION:			[zwave.node_cc.SECURITY, 0x81],
	SECURITY_MESSAGE_ENCAPSULATION_NONCE_GET:	[zwave.node_cc.SECURITY, 0xC1],

    });

    static no_route = [0, 0, 0, 0];

    /******************************************************************************
     *     initialization                                                         *
     ******************************************************************************/

    constructor(dev_file) {
	this.dev_file = dev_file;
	this.tx_options = 0x25; // ACK + AUTO_ROUTE + EXPLORE
	this.s0_network_key = [157, 88, 48, 81, 140, 226, 104, 69, 115, 189, 89, 252, 64, 219, 177, 80];
	this.api_cmd_mutex = new async_mutex();
	this.api_cmd_session_id = 1; // counter to increment for each new session
	this.node_send_queue = [];
    }

    async init() {
	// open serial port
	const stty_args = ["-F", this.dev_file, "raw", "-parenb", "cs8", "-cstopb", "115200"];
	const res = new Deno.Command("/usr/bin/stty", {args: stty_args}).outputSync();

	if (!res.success) {
	    console.log(String.fromCharCode.apply(null, res.stderr));
	    throw("stty failed");
	}

	this.serial = Deno.openSync(this.dev_file, {read: true, write: true});

	// S0 keys
	this.s0_key = await s0_key_gen(this.s0_network_key);
	this.s0_temp_key = await s0_key_gen(aes_zero);

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

    /******************************************************************************
     *     TX framing                                                             *
     ******************************************************************************/

    send_frame(...args) { // args must be numbers or arrays of numbers (incl. nested)
	args = args.flat(10);
	let buf = new Uint8Array(args);

	while (buf.length) {
	    const bytes_written = this.serial.writeSync(buf);
	    buf = buf.subarray(bytes_written);
	}

	return args.to_hex_bytes();
    }

    async send_data_frame(type, ...args) {
	const type_str = zwave.data_frame_type.get_key(type);
	const args_flat = args.flat(10);
	const len = args_flat.length + 2;
	let checksum = 0xff ^ type ^ len;
	args_flat.forEach((d) => {checksum ^= d});

	for (let n = 0; n < 3; ++n) {
	    const ack_timeout = new timeout(this.recv_ack_nak_can_or_timeout.bind(this, null), 1600);

	    const ack = await new Promise((resolve) => {
		this.send_data_frame_resolve = resolve;
		const frame_str = this.send_frame(zwave.frame_start.SOF, len, type, args_flat, checksum);
		log("\tTX", type_str, frame_str + ((n > 0) ? (" (retry #" + n + ")") : ""));
	    });

	    ack_timeout.cancel();

	    if (ack == zwave.frame_start.ACK) {
		return;
	    }

	    // backoff delay
	    await sleep(100 + (n * 1000));
	}

	throw("no ACK received for data frame");
    }

    send_ack_nak(frame_start) {
	log("\tTX", zwave.frame_start.get_key(frame_start), this.send_frame(frame_start));
    }

    /******************************************************************************
     *     RX framing                                                             *
     ******************************************************************************/

    async recv_byte() {
	const buf = new Uint8Array(1);

	while (true) {
	    const d = await this.serial.read(buf);

	    if (d == 1) {
		let ret = buf[0];
		this.recv_frame.push(ret);
		return ret;
	    } else if (d == null) {
		throw("serial port closed");
	    }
	}
    }

    recv_ack_nak_can_or_timeout(frame_start) {
	if (frame_start) {
	    // not timeout
	    log("\tRX", zwave.frame_start.get_key(frame_start), [frame_start].to_hex_bytes());
	}

	if (this.send_data_frame_resolve) {
	    this.send_data_frame_resolve(frame_start);
	    delete this.send_data_frame_resolve;
	}
    }

    async recv_loop() {
	while (true) {
	    this.recv_frame = [];
	    const frame_start = await this.recv_byte();

	    if ([zwave.frame_start.ACK, zwave.frame_start.NAK, zwave.frame_start.CAN].includes(frame_start)) {
		this.recv_ack_nak_can_or_timeout(frame_start);
	    } else if (frame_start == zwave.frame_start.SOF) {
		const len = await this.recv_byte();
		const type = await this.recv_byte();
		let expected_checksum = 0xff ^ type ^ len;

		for (let i = 2; i < len; ++i) {
		    expected_checksum ^= await this.recv_byte();
		}

		const checksum = await this.recv_byte();
		const type_str = zwave.data_frame_type.get_key(type);
		let frame_str = this.recv_frame.to_hex_bytes();
		log("\tRX", type_str, frame_str);

		if (checksum == expected_checksum) {
		    if ([zwave.data_frame_type.REQ, zwave.data_frame_type.RES].includes(type)) {
			this.send_ack_nak(zwave.frame_start.ACK);
			await this.recv_data_frame(type, this.recv_frame[3], this.recv_frame.slice(4, len + 1));
		    } else {
			log("\tRX ERROR bad type");
		    }
		} else {
		    log("\tRX ERROR bad checksum");
		    this.send_ack_nak(zwave.frame_start.NAK);
		}
	    } else {
		log("\tRX ERROR unexpected byte", [frame_start].to_hex_bytes());
	    }
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

	if (type == zwave.data_frame_type.REQ) {
	    if (cmd_id == zwave.api_cmd.BRIDGE_COMMAND_HANDLER) {
		await this.recv_bridge_command_handler(pld);
	    } else {
		log("\tRX ERROR unhandled unsolicited Request");
	    }
	} else {
	    log("\tRX ERROR unexpected Response");
	}
	console.log("-".repeat(80));

	while (this.node_send_queue.length) {
	    this.bridge_node_send(this.node_send_queue.shift());
	}
    }

    /******************************************************************************
     *     TX API commands                                                        *
     ******************************************************************************/

    // common
    async send_api_cmd(cmd) {
	this.api_cmd_mutex.lock();
	this.api_cmd_current = cmd;

	if (cmd.onreq && !cmd.req_id) {
	    // uses calbacks - append new sessio_id at the end of the frame
	    ++this.api_cmd_session_id;
	    if (this.api_cmd_session_id == 0) {
		this.api_cmd_session_id = 1;
	    }

	    cmd.session_id = this.api_cmd_session_id;
	    cmd.pld.push(cmd.session_id);
	    cmd.req_id = cmd.id;
	}

	log(zwave.api_cmd.get_key(cmd.id), ...(cmd.msg ?? []));

	const promise = new Promise((resolve) => {cmd.resolve = resolve});
	await this.send_data_frame(zwave.data_frame_type.REQ, cmd.id, ...(cmd.pld ?? []));

	if (!cmd.onres && !cmd.onreq) {
	    this.api_cmd_end();
	}

	await promise;
	delete this.api_cmd_current;
	this.api_cmd_mutex.unlock();
    }

    api_cmd_end(...msg) {
	if (msg.length > 0) {
	    log(...msg);
	}
	console.log("-".repeat(80));
	this.api_cmd_current.resolve();
    }

    encode_nodeid(nodeid) {
	return this.nodeid_16bit ? [(nodeid >> 8) & 0xff, nodeid & 0xff] : [nodeid & 0xff];
    }

    // TX API commands
    async soft_reset() {
	await this.send_api_cmd({
	    id: zwave.api_cmd.SOFT_RESET,
	    req_id: zwave.api_cmd.API_STARTED,
	    onreq: (pld) => {
		this.api_cmd_end("API started!");
	    }
	});
    }

    async set_default() {
	await this.send_api_cmd({
	    id: zwave.api_cmd.SET_DEFAULT,
	    pld: [],
	    onreq: (pld) => {
		this.api_cmd_end("Controller in default state!");
	    }
	});
    }

    async get_network_ids() {
	await this.send_api_cmd({
	    id: zwave.api_cmd.GET_NETWORK_IDS,
	    pld: [],
	    onres: (pld) => {
		this.home_id = pld.slice(0, 4);
		this.nodeid = pld[4];
		this.api_cmd_end("HomeID: " + this.home_id.to_hex_bytes(), "nodeid:" + this.nodeid);
	    }
	});
    }

    async get_init_data() {
	this.nodes = new Map();

	await this.send_api_cmd({
	    id: zwave.api_cmd.GET_INIT_DATA,
	    onres: (pld) => {
		const node_list_length = pld[2];

		if (node_list_length == (pld.length - 5)) {
		    for (let nodeid of pld.slice(3, 3 + node_list_length).get_bit_list(1)) {
			const node_info = {
			    nonce: Array(256),
			    nonce_id: 0
			}
			this.nodes.set(nodeid, node_info);
		    }
		    this.api_cmd_end("nodes: " + Array.from(this.nodes.keys()).join(" "));
		} else {
		    this.api_cmd_end("Invalid response");
		}
	    }
	});
    }

    async set_tx_status_report(enable) {
	await this.send_api_cmd({
	    msg: ["| Set TX Status Report: ", enable ? "enabled" : "disabled"],
	    id: zwave.api_cmd.API_SETUP,
	    pld: [0x02, enable ? 1 : 0],
	    onres: (pld) => {
		this.api_cmd_end(((pld.length == 2) && (pld[1] != 0)) ? "OK" : "FAIL");
	    }
	});
    }

    async set_nodeid_base_type(enable_16bit) {
	await this.send_api_cmd({
	    msg: ["| Set NodeID Base Type: ", enable_16bit ? "16-bit" : "8-bit"],
	    id: zwave.api_cmd.API_SETUP,
	    pld: [0x80, enable_16bit ? 2 : 1],
	    onres: (pld) => {
		if ((pld.length == 2) && (pld[1] != 0)) {
		    this.nodeid_16bit = enable_16bit;
		    this.api_cmd_end("OK");
		} else {
		    this.api_cmd_end("FAIL");
		}
	    }
	});
    }

    async add_node_to_network() {
	let nodeid;

	await this.send_api_cmd({
	    msg: ["Add any node"],
	    id: zwave.api_cmd.ADD_NODE_TO_NETWORK,
	    pld: [0xc1],
	    onreq: (pld) => {
		switch (pld[0]) {
		case 0x1: log("Network Inclusion Started"); break;
		case 0x2: log("Node found"); break;
		case 0x3: log("Inclusion ongoing (End Node)"); break;
		case 0x4: log("Inclusion ongoing (Controller Node)"); break;
		case 0x5:
		    nodeid = pld[1]; // TODO support 16-bit
		    this.api_cmd_end("Inclusion Completed (protocol part) - node:" + nodeid);
		    break;
		default:  this.api_cmd_end("Unexpected status:" + pld[0]);
		}
	    }
	});

	await this.send_api_cmd({
	    msg: ["Stop network inclusion"],
	    id: zwave.api_cmd.ADD_NODE_TO_NETWORK,
	    pld: [0xc5],
	    onreq: (pld) => {
		if (pld[0] == 0x6) {
		    this.api_cmd_end("Network Inclusion Stopped");
		} else {
		    this.api_cmd_end("Unexpected status:" + pld[0]);
		}
	    }
	});

	// repeat stop but this time no callback expected
	await this.send_api_cmd({
	    msg: ["Stop network inclusion (again)"],
	    id: zwave.api_cmd.ADD_NODE_TO_NETWORK,
	    pld: [0xc5, 0 /* fake session ID */]
	});

	if (nodeid) {
	    const node_info = {
		nonce: Array(256),
		nonce_id: 0
	    }
	    this.nodes.set(nodeid, node_info);
	    return nodeid;
	}
    }

    async remove_node_from_network(nodeid) {
	const cmd_id = nodeid ? zwave.api_cmd.REMOVE_SPECIFIC_NODE_FROM_NETWORK : zwave.api_cmd.REMOVE_NODE_FROM_NETWORK;

	await this.send_api_cmd({
	    msg: ["|", nodeid ? "Remove node:" + nodeid : "Remove any node"],
	    id: cmd_id,
	    pld: nodeid ? [0xc1, nodeid] : [c1],
	    onreq: (pld) => {
		switch (pld[0]) {
		case 0x1: log("Network Exclusion Started"); break;
		case 0x2: log("Node found"); break;
		case 0x3: log("Exclusion ongoing (End Node)"); break;
		case 0x4: log("Exclusion ongoing (Controller Node)"); break;
		case 0x6: this.api_cmd_end("Exclusion completed"); break;
		default:  this.api_cmd_end("Unexpected status:" + pld[0]);
		}
	    }
	});

	// no callback expected on the stop
	await this.send_api_cmd({
	    msg: ["|", "Stop network exclusion"],
	    id: cmd_id,
	    pld: [0xc5, 0 /* fake session ID */]
	});
    }

    async is_node_failed(nodeid) {
	await this.send_api_cmd({
	    id: zwave.api_cmd.IS_NODE_FAILED,
	    pld: [nodeid],
	    onres: (pld) => {
		if (pld[0] < 2) {
		    this.api_cmd_end("Failed:", (pld[0] == 1) ? "Yes" : "No");
		} else {
		    this.api_cmd_end("Unexpected response:" + pld[0]);
		}
	    }
	});
    }

    async remove_failed_node(nodeid) {
	await this.send_api_cmd({
	    msg: ["Remove node:" + nodeid],
	    id: zwave.api_cmd.REMOVE_FAILED_NODE,
	    pld: [nodeid],
	    onres: (pld) => {
		switch (pld[0]) {
		case 0x0: log("Failed node remove started"); break;
		case 0x1: log("Not primary controller"); break;
		case 0x2: log("No callback function"); break;
		case 0x3: log("Failed node not found"); break;
		case 0x4: log("Failed node remove process busy"); break;
		case 0x5: log("Failed node remove fail"); break;
		default:  log("Unexpected response:" + pld[0])
		}
	    },
	    onreq: (pld) => {
		switch (pld[0]) {
		case 0x0: this.api_cmd_end("Node OK (not removed)"); break;
		case 0x1: this.api_cmd_end("Failed node removed"); break;
		case 0x2: this.api_cmd_end("Failed node not removed"); break;
		default:  this.api_cmd_end("Unexpected status:" + pld[0]);
		}
	    }
	});
    }

    async bridge_node_send(cmd) {
	const node_cmd_str = zwave.node_cmd.get_key(cmd.cmd);
	let node_cmd = [cmd.cmd, cmd.pld ?? []].flat(10);

	const node = this.nodes.get(cmd.nodeid);

	if (!node) {
	    throw("non-existent node:" + cmd.nodeid);
	}

	if (cmd.s0_key) {
	    const nonce_promise = new Promise((resolve) => {node.nonce_resolve = resolve});
	    await this.security_nonce_get(cmd.nodeid);
	    const receiver_nonce = await nonce_promise;

	    node_cmd = await this.security_encapsulate(node_cmd, cmd.s0_key, cmd.nodeid, receiver_nonce);
	}

	await this.send_api_cmd({
	    msg: ["node:" + cmd.nodeid, "|", node_cmd_str, ...(cmd.msg ?? [])],
	    id: zwave.api_cmd.BRIDGE_NODE_SEND,
	    pld: [this.encode_nodeid(1), this.encode_nodeid(cmd.nodeid),
		  node_cmd.length, node_cmd, this.tx_options, zwave.no_route],
	    onres: (pld) => {
		if (!((pld.length == 1) && (pld[0] != 0))) {
		    this.api_cmd_end("FAIL");
		}
	    },
	    onreq: (pld) => {
		this.api_cmd_end("tx_status:" + pld[0]);
	    }
	});
    }

    /******************************************************************************
     *     RX API commands                                                        *
     ******************************************************************************/

    async recv_bridge_command_handler(pld) {
	// pld starts with first byte after cmd_id
	if (pld.length < (6 + (this.nodeid_16bit ? 2 : 0))) {
	    log("invalid command (too short)");
	    return;
	}

	const len_offset = this.nodeid_16bit ? 5 : 3;
	const cmd_offset = len_offset + 1;
	const len = pld[len_offset];
	const cmd_end = cmd_offset + len;

	if (!((len >= 2) && (cmd_end <= pld.length))) {
	    log("invalid command (pld doesn't fit)");
	    return;
	}

	// start a node command
	const cmd = {
	    msg: ["BRIDGE_COMMAND_HANDLER"],
	    nodeid: pld[len_offset - 1] + (pld[len_offset - 2] * (this.nodeid_16bit ? 256 : 0)),
	    cc: pld[cmd_offset],
	    id: pld[cmd_offset + 1],
	    pld: pld.slice(cmd_offset + 2, cmd_end)
	}

	cmd.msg.push("node:" + cmd.nodeid, "|");
	await this.recv_node_cmd(cmd);
    }

    /******************************************************************************
     *     TX node commands                                                       *
     ******************************************************************************/

    async security_encapsulate(cmd, key, receiver_nodeid, receiver_nonce) {
	// flatten to create a new array that will be encrypted - also to determine the length
	cmd = cmd.flat(10);

	// encrypt
	const sender_nonce = rand(8);
	const vec = sender_nonce.concat(receiver_nonce); // Initialization Vector

	for (let offset = 0; offset < cmd.length; offset += 16) {
	    await aes_ecb(key.enc, vec);
	    aes_xor(cmd, offset, vec, 0);
	}

	// authentication code
	vec.fill(0);
	const node_cmd = zwave.node_cmd.SECURITY_MESSAGE_ENCAPSULATION;
	const seq_info = 0; // no sequencing
	const auth_data = [sender_nonce, receiver_nonce, node_cmd[1],
			   this.nodeid, receiver_nodeid, cmd.length + 1, seq_info, cmd].flat();

	for (let offset = 0; offset < auth_data.length; offset += 16) {
	    aes_xor(vec, 0, auth_data, offset);
	    await aes_ecb(key.auth, vec);
	}

	// assemble encapsulated cmd
	return [node_cmd, sender_nonce,	seq_info, cmd, receiver_nonce[0], vec.slice(0, 8)].flat();
    }

    async no_operation(nodeid) {
	await this.bridge_node_send({
	    nodeid: nodeid,
	    cmd: zwave.node_cmd.NO_OPERATION
	});
    }

    async switch_binary_set(nodeid, val) {
	await this.bridge_node_send({
	    msg: ["value:" + val],
	    nodeid: nodeid,
	    cmd: zwave.node_cmd.SWITCH_BINARY_SET,
	    pld: [val]
	});
    }

    async switch_binary_get(nodeid) {
	await this.bridge_node_send({
	    nodeid: nodeid,
	    cmd: zwave.node_cmd.SWITCH_BINARY_GET
	});
    }

    async security_scheme_get(nodeid) {
	await this.bridge_node_send({
	    nodeid: nodeid,
	    cmd: zwave.node_cmd.SECURITY_SCHEME_GET,
	    pld: [0]
	});
    }

    async security_nonce_get(nodeid) {
	await this.bridge_node_send({
	    nodeid: nodeid,
	    cmd: zwave.node_cmd.SECURITY_NONCE_GET
	});
    }

    async network_key_set(nodeid) {
	await this.bridge_node_send({
	    nodeid: nodeid,
	    cmd: zwave.node_cmd.NETWORK_KEY_SET,
	    pld: this.s0_network_key,
	    s0_key: this.s0_temp_key
	});
    }

    /******************************************************************************
     *     RX node commands                                                       *
     ******************************************************************************/

    async recv_node_cmd(cmd) {
	cmd.node = this.nodes.get(cmd.nodeid);

	if (!cmd.node) {
	    log(...cmd.msg, "non-existent node:" + cmd.nodeid);
	    return;
	}

	for (let e of Object.entries(zwave.node_cmd)) {
	    if ((e[1][0] == cmd.cc) && (e[1][1] == cmd.id)) {
		cmd.cmd = e[1];
		cmd.msg.push(e[0], "|");
	    }
	}

	switch (cmd.cmd) {
	case zwave.node_cmd.SWITCH_BINARY_REPORT: this.recv_switch_binary_report(cmd); return;
	case zwave.node_cmd.SECURITY_NONCE_GET: this.recv_security_nonce_get(cmd); return;
	case zwave.node_cmd.SECURITY_NONCE_REPORT: this.recv_security_nonce_report(cmd); return;
	case zwave.node_cmd.SECURITY_SCHEME_REPORT: this.recv_security_scheme_report(cmd); return;
	case zwave.node_cmd.SECURITY_MESSAGE_ENCAPSULATION: await this.recv_security_message_encapsulation(cmd); return
	case zwave.node_cmd.NETWORK_KEY_VERIFY: await this.recv_network_key_verify(cmd); return
	}

	log(...cmd.msg, "unsupported");
    }

    recv_switch_binary_report(cmd) {
	if (cmd.pld.length != 1) {
	    log(...cmd.msg, "incorrect length");
	    return;
	}

	const val = cmd.pld[0];
	log(...cmd.msg, "value:" + val);
	cmd.node.val = val;
    }

    recv_security_nonce_report(cmd) {
	if (cmd.pld.length != 8) {
	    log(...cmd.msg, "incorrect length");
	    return;
	}

	const nonce = cmd.pld;
	log(...cmd.msg, "nonce:" + nonce);

	if (cmd.node.nonce_resolve) {
	    cmd.node.nonce_resolve(nonce);
	    delete cmd.node.nonce_resolve;
	}
    }

    recv_security_nonce_get(cmd) {
	if (cmd.pld.length != 0) {
	    log(...cmd.msg, "incorrect length");
	    return;
	}

	const node = cmd.node;
	const nonce_id = (node.nonce_id + 1) % 256;
	const nonce = rand(8);
	nonce[0] = nonce_id;
	node.nonce[nonce_id] = nonce;
	node.nonce_id = nonce_id;

	// disable after 3 seconds
	setTimeout(() => {nonce.length = 0}, 3000);

	this.node_send_queue.push({
	    nodeid: cmd.nodeid,
	    cmd: zwave.node_cmd.SECURITY_NONCE_REPORT,
	    pld: nonce
	});
    }

    recv_security_scheme_report(cmd) {
	if (cmd.pld.length != 1) {
	    log(...cmd.msg, "incorrect length");
	    return;
	}

	const val = cmd.pld[0];
	log(...cmd.msg, "supported:" + val);

	if (cmd.node.scheme_resolve) {
	    cmd.node.scheme_resolve(val);
	    delete cmd.node.scheme_resolve;
	}
    }

    recv_network_key_verify(cmd) {
	if (cmd.pld.length != 0) {
	    log(...cmd.msg, "incorrect length");
	    return;
	}

	if (cmd.node.network_key_verify_resolve) {
	    cmd.node.network_key_verify_resolve(val);
	    delete cmd.node.network_key_verify_resolve;
	}
    }

    async recv_security_message_encapsulation(cmd) {
	const encapsulated_cmd_len = cmd.pld.length - 18;

	if (encapsulated_cmd_len < 2) {
	    log(...cmd.msg, "incorrect length");
	    return;
	}

	// extract fields
	const sender_nonce = cmd.pld.slice(0, 8);
	const seq_info = cmd.pld[8];

	if (seq_info != 0) {
	    log(...cmd.msg, "unexpected sequence byte:" + seq_info);
	    return;
	}

	const encapsulated_cmd = cmd.pld.slice(9, 9 + encapsulated_cmd_len);
	const receiver_nonce_id = cmd.pld[9 + encapsulated_cmd_len];
	const mac = cmd.pld[10 + encapsulated_cmd_len];

	// receiver nonce
	const receiver_nonce = cmd.node.nonce[receiver_nonce_id];

	if (!receiver_nonce) {
	    log(...cmd.msg, "no receiver nonce:" + receiver_nonce_id);
	    return;
	}

	if (receiver_nonce.length < 8) {
	    log(...cmd.msg, "receiver nonce expired");
	    return;
	}

	// decode
	const vec = sender_nonce.concat(receiver_nonce); // Initialization Vector

	for (let offset = 0; offset < encapsulated_cmd.length; offset += 16) {
	    await aes_ecb(this.s0_key.enc, vec);
	    aes_xor(encapsulated_cmd, offset, vec, 0);
	}

	// authentication code check
	vec.fill(0);
	const receiver_nodeid = 1;
	const auth_data = [sender_nonce, receiver_nonce, cmd.id, cmd.nodeid, receiver_nodeid,
			   encapsulated_cmd.length + 1, seq_info, encapsulated_cmd].flat();

	for (let offset = 0; offset < auth_data.length; offset += 16) {
	    aes_xor(vec, 0, auth_data, offset);
	    await aes_ecb(this.s0_key.auth, vec);
	}

	for (let i = 0; i < 8; ++i) {
	    if (vec[i] != mac[i]) {
		log(...cmd.msg, "incorrect MAC:", vec, mac);
		return;
	    }
	}

	// dispatch encapsulated cmd
	await this.recv_node_cmd({
	    msg: cmd.msg,
	    nodeid: cmd.nodeid,
	    cc: encapsulated_cmd[0],
	    id: encapsulated_cmd[1],
	    pld: encapsulated_cmd.slice(2),
	    secure: true
	});
    }

    /******************************************************************************
     *     flows                                                                  *
     ******************************************************************************/

    async add_secure_node_to_network() {
	const nodeid = await add_node_to_network();

	if (!nodeid) {
	    return;
	}

	const node = this.nodes.get(nodeid);

	const scheme_promise = new Promise((resolve) => {node.scheme_resolve = resolve});
	await this.security_scheme_get(nodeid);
	const scheme_supported = await scheme_promise;

	const key_verify_promise = new Promise((resolve) => {node.key_verify_resolve = resolve});
	await this.network_key_set(nodeid);
	await key_verify_promise;
    }
}
