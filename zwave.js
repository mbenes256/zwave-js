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

function bigint_from_array(arr) {
    let n = 0n;
    // little endian
    for (let i = arr.length - 1; i >= 0; --i) {
	n = (n << 8n) | BigInt(arr[i]);
    }
    return n;
}

function encode_lsb_first(n, bytes) {
    const arr = [];
    n = BigInt(n);

    while ((bytes--) > 0) {
	arr.push(Number(n & 0xffn))
	n >>= 8n;
    }

    return arr;
}

function encode_msb_first(n, bytes) {
    return encode_lsb_first(n, bytes).reverse();
}

function aes_padding(current_length, val = 0) {
    const len = (aes_blocksize - (current_length % aes_block_size)) % aes_block_size;
    return Array(len).fill(val);
}

function hex_bytes(arr) {
    return arr.map((e) => (e & 0xff).toString(16).padStart(2, "0")).join(" ");
}

function array_from_hex(str) {
    return str.match(/[0-9a-fA-F]{2}/g).map((s) => Number.parseInt(s, 16));
}

function pack_fmt(args, fmt) {
    const arr = [];

    for (let [arg_name, arg_bytes] of Object.entries(fmt)) {
	arg_name = arg_name.replace(/^_*/,"");
	const arg_val = args[arg_name];
	let arg_arr;

	if (arg_val == undefined) {
	    // fill with 0 if not provided
	    arg_arr = Array(arg_bytes + (arg_bytes == 0)).fill(0);
	} else {
	    arg_arr = [arg_val].flat();
	}

	// strip or pad to the required length for fixed-length only
	if (arg_bytes > 0) {
	    arg_arr = arg_arr.slice(0, arg_bytes);
	    arg_arr.push(...Array(arg_bytes - arg_arr.length).fill(0));
	}

	// add to result
	arr.push(...arg_arr);
    }

    return arr;
}

function unpack_fmt(arr, fmt) {
    const args = {};
    let offset = 0;

    for (let [arg_name, arg_bytes] of Object.entries(fmt)) {
	arg_name = arg_name.replace(/^_*/,"");

	// zero-length takes the remainder of array
	if (arg_bytes == 0) {
	    arg_bytes = arr.length - offset;
	}

	// extract chunk
	const arg_arr = arr.slice(offset, offset + arg_bytes);
	offset += arg_bytes;

	// check if underflow
	if (arg_arr.length < arg_bytes) {
	    return;
	}

	// add to args
	if (arg_bytes == 1) {
	    // single-byte convert to number
	    args[arg_name] = arg_arr[0];
	} else if (arg_bytes > 1) {
	    args[arg_name] = arg_arr;
	}
    }

    // check if we consumed all pld
    if (arr.length > offset) {
	return;
    }

    return args;
}

function print_fmt(args, fmt) {
    const msg = [];

    if (args) {
	for (let [arg_name, arg_bytes] of Object.entries(fmt)) {
	    if (!arg_name.startsWith("_")) {
		const arg_val = args[arg_name];

		if (typeof(arg_val) == "number") {
		    msg.push(arg_name + ":" + arg_val);
		} else if (Array.isArray(arg_val)) {
		    msg.push(arg_name + ": " + hex_bytes(arg_val));
		}
	    }
	}
    }

    return msg;
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
	// notify we are no longer holding the mutex
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

// - all functions assume AES-128
// - all buffers are Arrays of Numbers (each element represents a single byte)
// - resulting buffers modified in place and returned

const aes_blocksize = 16;

// gnerate a block with constant value "val"
function aes_block(val) {
    return Array(aes_blocksize).fill(val);
}

// generate an AES-128 CryptoKey from raw data
async function aes_key_gen(raw) {
    raw = new Uint8Array(raw);
    return await crypto.subtle.importKey("raw", raw, "AES-CBC", false, ["encrypt"]);
}

// encode single block "vec" (modified in place) and return it
export async function aes_ecb(key, vec) {
    const plaintext = new Uint8Array(vec);
    const zero_iv = new Uint8Array(aes_blocksize);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name: "AES-CBC", iv: zero_iv}, key, plaintext));

    for (let i = 0; i < aes_blocksize; ++i) {
	vec[i] = ciphertext[i];
    }

    return vec;
}

// XOR vector "dst" (modified in place) with "src" and return it
function aes_xor(dst, dst_offset, src, src_offset, max_length = 16) {
    const length = Math.min(dst.length - dst_offset, src.length - src_offset, max_length);

    for (let i = 0; i < length; ++i) {
	dst[i + dst_offset] ^= src[i + src_offset];
    }

    return dst;
}

// encrypt "data" (modified in place) using OFB mode and return it
async function aes_encrypt_ofb(key, iv, data) {
    for (let offset = 0; offset < data.length; offset += aes_blocksize) {
	await aes_ecb(key, iv);
	aes_xor(data, offset, iv, 0);
    }

    return data;
}

// return CBC-MAC of "data"
async function aes_cbc_mac(key, data, trim_bytes = 8) {
    const vec = aes_block(0);

    for (let offset = 0; offset < data.length; offset += aes_blocksize) {
	aes_xor(vec, 0, data, offset);
	await aes_ecb(key, vec);
    }

    return vec.slice(0, trim_bytes);
}

// return AES-CMAC of "data"
async function aes_cmac(key, data, trim_bytes = 8) {
    data = Array.from(data); // copy because we will modify

    // generate and cache subkeys in the key object
    if (!key.cmac_subkey) {
	key.cmac_subkey = [];
	const vec = await aes_ecb(key, aes_block(0)); // L

	// generate K1/K2 in identical steps
	while (key.cmac_subkey.length < 2) {
	    let overflow = 0;

	    // shift left by 1
	    for (let i = 15; i >= 0; --i) {
		vec[i] = (vec[i] << 1) | overflow;
		overflow = vec[i] >> 8;
		vec[i] &= 0xff;
	    }

	    vec[15] ^= overflow ? 0x87 : 0; // xor with const_Rb if overflow
	    key.cmac_subkey.push(Array.from(vec));
	};
    }

    let subkey = key.cmac_subkey[0]; // K1

    // in case padding needed
    if ((data.length == 0) || (data.length % aes_blocksize)) {
	data.push(0x80, ...aes_padding(data.length + 1));
	subkey = key.cmac_subkey[1]; // K2
    }

    aes_xor(data, data.length - aes_blocksize, subkey, 0); // last block
    return await aes_cbc_mac(key, data, trim_bytes);
}

// return CCM-encrypted packet consisting of "aad", encrypted "data" (modified in place) and MAC
async function aes_encrypt_ccm(key, nonce, aad, data, M = 8, L = 2) {
    // authentication
    const auth_flags = 0x40 /* Adata */ + (((M - 2) / 2) << 3) + (L - 1);
    const auth_data = [auth_flags, nonce, encode_msb_first(data.length, L),
		       encode_msb_first(aad.length, 2), aad, aes_padding(aad.length + 2),
		       data, aes_padding(data.length)].flat();
    const T = await aes_cbc_mac(key, auth_data);

    // encrypt data
    const enc_flags = L - 1;
    for (let offset = 0; offset < data.length; offset += aes_blocksize) {
	const A = [enc_flags, nonce, encode_msb_first((offset / aes_blocksize ) + 1, 2)].flat();
	aes_xor(data, offset, await aes_ecb(key, A), 0);
    }

    // encrypt MAC and concatenate all
    aes_xor(T, 0, await aes_ecb(key, [enc_flags, nonce, 0, 0].flat()), 0);
    return [aad, data, T.slice(0, M)].flat();
}

// CTR_DRBG random number generator
class aes_ctr_drbg {
    async init(seed) {
	this.K = await aes_key_gen(aes_block(0));
	this.V = aes_block(0);
	await this.update(seed);
    }

    async step() {
	for (let i = 15; (i >= 0) && ((++V[i]) == 256); --i) V[i] = 0; // increment V
	return await aes_ecb(this.K, Array.from(this.V)); // encrypt V
    }

    async update(data) {
	aes_xor(data, 0, await this.step(), 0);
	aes_xor(data, aes_blocksize, await this.step(), 0);
	this.K = await aes_key_gen(data.slice(0, aes_blocksize));
	this.V = data.slice(aes_blocksize);
    }

    async gen(bytes) {
	const data = [];

	while (data.length < bytes) {
	    data.push(...await this.step());
	}

	await this.update(aes_block(0))
	return data.slice(0, bytes);
    }
}

/******************************************************************************
 *     security utils                                                         *
 ******************************************************************************/

async function s0_key_gen(network_key_raw) {
    const network_key = await aes_key_gen(network_key_raw);
    const auth_key_raw = await aes_ecb(network_key, aes_block(0x55));
    const enc_key_raw = await aes_ecb(network_key, aes_block(0xaa));

    return {auth: await aes_key_gen(auth_key_raw), enc: await aes_key_gen(enc_key_raw)}
}

function s2_curve25519_scalarmult(k, u) {
    k = bigint_from_array(k);
    u = bigint_from_array(u);

    // curve25519 constants
    const p = 2n**255n - 19n;
    const A = 486662n;
    const A_minus2_div4 = (A - 2n) / 4n;

    // modular arithmetic
    const fadd = (a, b) => (a + b) % p;
    const fsub = (a, b) => (p + a - b) % p;
    const fmul = (a, b) => (a * b) % p;
    const fpow2 = (a) => fmul(a, a);
    const fpow = (a, b) => (b == 1) ? a : fmul(fpow2(fpow(a, b >> 1n)), (b & 1n) ? a : 1n);
    const fdiv = (a, b) => fmul(a, fpow(b, p - 2n));

    // clamp key
    k = (k | 2n**254n) & (2n**255n - 8n);

    // Montgomery ladder - loop through bits of k
    let [a, b, c, d] = [1n, u, 0n, 1n];

    for (let i = 254n; i >= 0n; --i) {
	const swap = (k >> i) & 1n;
	[a, b, c, d] = swap ? [b, a, d, c] : [a, b, c, d];

	let e = fadd(a, c);
	a = fsub(a, c);
	c = fadd(b, d);
	b = fsub(b, d);
	d = fpow2(e);
	let f = fpow2(a);
	a = fmul(c, a);
	c = fmul(b, e);
	e = fadd(a, c);
	a = fsub(a, c);
	b = fpow2(a);
	c = fsub(d, f);
	a = fmul(c, A_minus2_div4);
	a = fadd(a, d);
	c = fmul(c, a);
	a = fmul(d, f);
	d = fmul(b, u);
	b = fpow2(e);

	[a, b, c, d] = swap ? [b, a, d, c] : [a, b, c, d];
    }

    return encode_lsb_first(fdiv(a, c), 16);
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
	return encode_msb_first(nodeid, this.nodeid_16bit ? 2 : 1);
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

    async request_node_information(nodeid) {
	return await this.send_api_cmd({
	    id: zwave.api_cmd.REQUEST_NODE_INFORMATION,
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

/******************************************************************************
 *     zwave_node                                                             *
 ******************************************************************************/

export class zwave_node {
    constructor(z, nodeid) {
	this.z = z;
	this.nodeid = nodeid;
	this.mutex = new async_mutex();

	// this object will be populated with receive callbacks
	this.recv = {};

	// let each class initialize its data structures
	for (let cc_def of zwave_cc._cc_id_map.values()) {
	    cc_def.init?.(this);
	}

	// populate request functions
	for (let [cmd_name, cmd_def] of zwave_cc._cmd_name_map.entries()) {
	    if (cmd_def.encode) {
		this[cmd_name] = this.run_cmd.bind(this, cmd_def);
	    }
	}
    }

    async run_cmd(cmd_def, args = {}, options = {}) {
	// generate
	let cmd = await this.gen_cmd(cmd_def, args);
	const cmd_orig = cmd;

	// encapsulate
	if (options.epid > 0) {
	    cmd_orig.epid = options.epid;
	    cmd = await zwave_cc.MULTI_CHANNEL.encapsulate(cmd);
	}

	if (options.security == 0) {
	    cmd = await zwave_cc.SECURITY.encapsulate(cmd);

	    if (typeof(cmd) == "string") {
		return this.error(cmd, cmd_orig);
	    }
	}

	// shortcut for report commands to avoid deadlock
	if (cmd_def.is_report_cmd) {
	    return await this.z.bridge_node_send(cmd);
	}

	// requests allowed only one at a time
	await this.mutex.lock();
	this.cmd_current = cmd_orig;
	const report = await this.send_and_report_cmd(cmd);
	delete this.cmd_current;
	this.mutex.unlock();

	if (typeof(report) == "string") {
	    return this.error(report, cmd_orig);
	}

	return report;
    }

    // generate command object, including encoding
    async gen_cmd(cmd_def, args) {
	const cmd = {
	    node: this,
	    def: cmd_def,
	    id: [cmd_def.cc.id, cmd_def.id],
	    args: args,
	    msg: [cmd_def.name],
	}

	if (cmd_def.report_cmd) {
	    cmd.report_cmd = cmd_def.report_cmd;
	}

	await cmd_def.encode(cmd);
	return cmd;
    }

    error(msg, cmd) {
	this.z.log_func("ERROR:", msg, "| node:" + this.nodeid, ...cmd.msg);
	this.z.log_func();
	return false;
    }

    async send_and_report_cmd(cmd) {
	if (!await this.z.bridge_node_send(cmd)) {
	    // send failed
	    return false;
	}

	// retrieve original non-encapsulated command
	const cmd_orig = this.cmd_current;

	if (!cmd_orig.report_cmd) {
	    // not expecting report
	    return true;
	}

	// wait for report
	const report_promise = new Promise((resolve) => {cmd_orig.report = resolve});
	const cmd_timeout = new timeout(cmd_orig.report.bind(null, "timeout"), 1000 * (cmd_orig.timeout ?? 1));
	const report = await report_promise;
	cmd_timeout.cancel();
	return report;
    }

    async recv_cmd(cmd) {
	cmd.node = this;
	let cmd_def;

	while (true) {
	    // decode
	    cmd_def = zwave_cc._cc_id_map.get(cmd.id[0])?._cmd_id_map.get(cmd.id[1]);

	    if (!cmd_def?.decode) {
		cmd.msg.push("unsupported command for receive:", hex_bytes(cmd.id));
		return;
	    }

	    cmd.msg.push(cmd_def.name);
	    await cmd_def.decode(cmd);

	    if (!cmd.args) {
		cmd.msg.push("bad encoding");
		return;
	    }

	    if (!cmd.args.cmd) {
		// not encapuslated
		break;
	    }

	    // encapsulated - replace id/pld and repeat
	    cmd.id = cmd.args.cmd.id;
	    cmd.pld = cmd.args.cmd.pld;
	}

	// check if this is a report for a current request
	const cmd_req = this.cmd_current;

	if (cmd_req && (cmd_req.report_cmd == cmd_def) && (cmd_req.epid == cmd.epid)) {
	    cmd_req.report(cmd.args);
	} else {
	    if (cmd.epid > 0) {
		// add epid to args
		cmd.args.epid = cmd.epid;
	    }

	    // user callback
	    this.recv[cmd_def.name]?.(cmd.args);
	}
    }
}

/******************************************************************************
 *     Command Class definitions                                              *
 ******************************************************************************/

const zwave_cc = {
    index_it() {
	this._cc_id_map = new Map();
	this._cmd_name_map = new Map();

	// loop through classes
	for (let [cc_name, cc_def] of Object.entries(this)) {
	    if (cc_def.id != undefined) {
		this._cc_id_map.set(cc_def.id, cc_def);
		cc_def.name = cc_name;
		cc_def._cmd_id_map = new Map();

		// loop through commands
		for (let [cmd_name, cmd_def] of Object.entries(cc_def.cmd)) {
		    if (cmd_def.id != undefined) {
			cc_def._cmd_id_map.set(cmd_def.id, cmd_def);
			cmd_def.name = cmd_name;
			cmd_def.cc = cc_def;
			this._cmd_name_map.set(cmd_name, cmd_def);

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

	// convert report_cmd from string to cmd_def now that all commands are indexed
	for (let [cmd_name, cmd_def] of this._cmd_name_map.entries()) {
	    if (cmd_def.report_cmd) {
		cmd_def.report_cmd = this._cmd_name_map.get(cmd_def.report_cmd);
		cmd_def.report_cmd.is_report_cmd = true;
	    }
	}
    }
};

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
 *   report_cmd: <string name of command that is a response to this command>
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
 *   epid: multi-channel endpoint id
 */

zwave_cc.BINARY_SWITCH = {
    id: 0x25,
    cmd: {
	SWITCH_BINARY_SET: {id: 0x01, encode_fmt: {value: 1}},
	SWITCH_BINARY_GET: {id: 0x02, encode_fmt: {}, report_cmd: "SWITCH_BINARY_REPORT"},
	SWITCH_BINARY_REPORT: {id: 0x03, decode_fmt: [{value: 1, target: 1, duration: 1}, {value: 1}]}
    }
};

zwave_cc.BINARY_SENSOR = {
    id: 0x30,
    cmd: {
	SENSOR_BINARY_REPORT: {id: 0x03, decode_fmt: [{value: 1, type: 1}, {value: 1}]}
    }
};

zwave_cc.CONFIGURATION = {
    id: 0x70,
    cmd: {
	CONFIGURATION_SET: {
	    id: 0x04,
	    encode(cmd) {
		const [param, size, value] = [cmd.args.param & 0xff, cmd.args.size, cmd.args.value];
		if (![1, 2, 4].includes(size)) {
		    throw("unsupported size: " + size);
		}

		const val_buf = new Uint8Array(size);
		const dv = new DataView(val_buf.buffer);

		if (size == 1) {
		    dv.setInt8(0, value);
		} else if (size == 2) {
		    dv.setInt16(0, value);
		} else {
		    dv.setInt32(0, value);
		}

		cmd.pld = [param, size, Array.from(val_buf)],
		cmd.msg.push("param:" + param, "size:" + size, "value:" + value);
	    }
	},
	CONFIGURATION_GET: {id: 0x05, report_cmd: "CONFIGURATION_REPORT", encode_fmt: {param: 1}},
	CONFIGURATION_REPORT: {
	    id: 0x06,
	    decode(cmd) {
		let value, param, size;

    		if (cmd.pld.length >= 3) {
		    param = cmd.pld[0];
		    size = cmd.pld[1];
		    const dv = new DataView((new Uint8Array(cmd.pld.slice(2))).buffer);

		    if (size <= dv.byteLength) {
			if (size == 1) {
			    value = dv.getInt8(0);
			} else if (size == 2) {
			    value = dv.getInt16(0);
			} else if (size == 4) {
			    value = dv.getInt32(0);
			}
		    }
		}

		if (value != undefined) {
		    cmd.args = {param, size, value};
		    cmd.msg.push("param:" + param, "size:" + size, "value:" + value);
		} else {
		    cmd.msg.push("bad encoding");
		}
	    }
	}
    }
};

zwave_cc.BATTERY = {
    id: 0x80,
    cmd: {
	BATTERY_GET: {id: 0x02, encode_fmt: {}, report_cmd: "BATTERY_REPORT"},
	BATTERY_REPORT: {id: 0x03, decode_fmt: [{level: 1, flags: 2}, {level: 1}]}
    }
};

zwave_cc.NOTIFICATION = {
    id: 0x71,
    cmd: {
	NOTIFICATION_REPORT: {id: 0x05, decode_fmt: {__unused1: 4, type: 1, state: 1, __unused2: 0}}
    }
};

zwave_cc.WAKE_UP = {
    id: 0x84,
    cmd: {
	WAKE_UP_NOTIFICATION: {id: 0x07, decode_fmt: {}}
    }
};

zwave_cc.MULTI_CHANNEL = {
    id: 0x60,
    async encapsulate(cmd) {
	return await cmd.node.gen_cmd(this.cmd.MULTI_CHANNEL_CMD_ENCAP, {cmd});
    },
    cmd: {
	MULTI_CHANNEL_CMD_ENCAP: {
	    id: 0x0d,
	    encode(cmd) {
		cmd.pld = [0, cmd.args.cmd.epid, cmd.args.cmd.id, cmd.args.cmd.pld].flat();
		cmd.msg.push("epid:" + cmd.args.cmd.epid, "|", ...cmd.args.cmd.msg);
	    },
	    decode(cmd) {
		if (cmd.pld.length < 4) {
		    cmd.msg.push("bad encoding");
		    return;
		}

		cmd.epid = cmd.pld[0];
		cmd.args = {cmd: {id: cmd.pld.slice(2, 4), pld: cmd.pld.slice(4)}};
		cmd.msg.push("epid:" + cmd.epid, "|");
	    }
	}
    }
};

zwave_cc.SECURITY = {
    id: 0x98,
    init(node) {
	node.s0 = {nonce: Array(256), nonce_id: 0};
	node.recv.SECURITY_NONCE_GET = this.send_nonce_report.bind(null, node);
    },
    async inclusion(node) {
	if (await node.SECURITY_SCHEME_GET()) {
	    return await node.NETWORK_KEY_SET({key: node.z.s0_key});
	}
    },
    send_nonce_report(node) {
        const nonce_id = (node.s0.nonce_id + 1) % 256;
        const nonce = rand(8);
        nonce[0] = nonce_id;
        node.s0.nonce[nonce_id] = nonce;
        node.s0.nonce_id = nonce_id;

        // disable after 3 seconds
        setTimeout(() => {nonce.length = 0}, 3000);

	// send
	node.SECURITY_NONCE_REPORT({nonce});
    },
    async encapsulate(cmd) {
	const node = cmd.node;
	const z = node.z;
	const key = (cmd.def == this.cmd.NETWORK_KEY_SET) ? z.s0_temp_key : z.s0_key;
	const report = await cmd.node.run_cmd(this.cmd.SECURITY_NONCE_GET);

	if (!report) {
	    return "no receiver_nonce for S0 encapsulation";
	}

	const receiver_nonce = report.nonce;
	return await node.gen_cmd(this.cmd.SECURITY_MESSAGE_ENCAPSULATION, {cmd, key, receiver_nonce});
    },
    cmd: {
	SECURITY_SCHEME_GET: {id: 0x04, report_cmd: "SECURITY_SCHEME_REPORT", encode_fmt: {supported: 1}},
	SECURITY_SCHEME_REPORT: {id: 0x05, decode_fmt: {supported: 1}},
	NETWORK_KEY_SET: {id: 0x06, report_cmd: "NETWORK_KEY_VERIFY", encode_fmt: {key: 16}},
	NETWORK_KEY_VERIFY: {id: 0x07, decode_fmt: {}},
	SECURITY_NONCE_GET: {id: 0x40, report_cmd: "SECURITY_NONCE_REPORT", encode_fmt: {}, decode_fmt: {}},
	SECURITY_NONCE_REPORT: {id: 0x80, encode_fmt: {nonce: 8}, decode_fmt: {nonce: 8}},
	SECURITY_MESSAGE_ENCAPSULATION: {
	    id: 0x81,
	    async encode(cmd) {
		// encrypt
		const encrypted_pld = [0 /* seq_info */, cmd.args.cmd.id, cmd.args.cmd.pld ?? []].flat(10);
		const sender_nonce = rand(8);
		const receiver_nonce = cmd.args.receiver_nonce;
		await aes_encrypt_ofb(cmd.args.key.enc, sender_nonce.concat(receiver_nonce), encrypted_pld);

		// authentication code
		const auth_data = [sender_nonce, receiver_nonce, cmd.id[1],
				   cmd.node.z.nodeid, cmd.node.nodeid, encrypted_pld.length, encrypted_pld].flat();
		const mac = await aes_cbc_mac(cmd.args.key.auth, auth_data);

		// encapsulate
		cmd.pld = [sender_nonce, encrypted_pld, receiver_nonce[0], mac];
		cmd.msg.push("|", ...cmd.args.cmd.msg);
	    },
	    async decode(cmd) {
		const encrypted_pld_len = cmd.pld.length - 17; // IV, MAC, receiver nonce identifier not included

		if (encrypted_pld_len < 3) {
		    cmd.msg.push("bad encoding");
		    return;
		}

		// extract fields
		const sender_nonce = cmd.pld.slice(0, 8);
		const receiver_nonce_id_offset = 8 + encrypted_pld_len;
		const encrypted_pld = cmd.pld.slice(8, receiver_nonce_id_offset);
		const receiver_nonce_id = cmd.pld[receiver_nonce_id_offset];
		const mac = cmd.pld.slice(receiver_nonce_id_offset + 1);

		// receiver nonce
		const receiver_nonce = cmd.node.s0.nonce[receiver_nonce_id];

		if (!receiver_nonce) {
		    cmd.msg.push("no receiver nonce:" + receiver_nonce_id);
		    return;
		}

		delete cmd.node.s0.nonce[receiver_nonce_id];

		if (receiver_nonce.length < 8) {
		    cmd.msg.push("receiver nonce expired");
		    return;
		}

		// authentication code check
		const key = cmd.node.z.s0_key;
		const auth_data = [sender_nonce, receiver_nonce, cmd.id[1], cmd.node.nodeid, cmd.node.z.nodeid,
				   encrypted_pld_len, encrypted_pld].flat();
		const expected_mac = await aes_cbc_mac(key.auth, auth_data);

		for (let i = 0; i < 8; ++i) {
		    if (expected_mac[i] != mac[i]) {
			cmd.msg.push("incorrect MAC");
			return;
		    }
		}

		// decrypt
		await aes_encrypt_ofb(key.enc, sender_nonce.concat(receiver_nonce), encrypted_pld);

		// dispatch encapsulated cmd
		const seq_info = encrypted_pld[0];

		if (seq_info != 0) {
		    cmd.msg.push("unexpected sequence byte:" + seq_info);
		    return;
		}

		cmd.args = {cmd: {id: encrypted_pld.slice(1, 3), pld: encrypted_pld.slice(3)}};
		cmd.msg.push("|");
	    }
	}
    }
};

zwave_cc.SECURITY_2 = {
    id: 0x9f,
    cmd: {
	SECURITY_2_NONCE_GET: {
	    id: 0x01,
	    encode(cmd) {
		cmd.pld = [cmd.node.s2.seq_num++];
	    }
	},
	SECURITY_2_NONCE_REPORT: {id: 0x02},
	SECURITY_2_MESSAGE_ENCAPSULATION: {id: 0x03},
	KEX_GET: {id: 0x04},
	KEX_REPORT: {id: 0x05},
	KEX_SET: {id: 0x06},
	KEX_FAIL: {id: 0x07},
	PUBLIC_KEY_REPORT: {id: 0x08},
	SECURITY_2_NETWORK_KEY_GET: {id: 0x09},
	SECURITY_2_NETWORK_KEY_REPORT: {id: 0x0a},
	SECURITY_2_NETWORK_KEY_VERIFY: {id: 0x0b},
	SECURITY_2_TRANSFER_END: {id: 0x0c},
	SECURITY_2_COMMANDS_SUPPORTED_GET: {id: 0x0d},
	SECURITY_2_COMMANDS_SUPPORTED_REPORT: {id: 0x0e}
    }
};

zwave_cc.index_it();
