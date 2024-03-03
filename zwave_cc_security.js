import {bigint_from_array, encode_lsb_first, encode_msb_first, rand, hex_bytes, sleep} from "./zwave_utils.js"

export const zwave_cc_security = {};

/******************************************************************************
 *     AES utils                                                              *
 ******************************************************************************/

// - all functions assume AES-128
// - all buffers are Arrays of Numbers (each element represents a single byte)

const aes_blocksize = 16;

// gnerate a block with constant value "val"
function aes_block(val) {
    return Array(aes_blocksize).fill(val);
}

// generate an array of padding required to append to an array of "current_length" to read multiple of block size
function aes_padding(current_length, val = 0) {
    const len = (aes_blocksize - (current_length % aes_blocksize)) % aes_blocksize;
    return Array(len).fill(val);
}

// generate an AES-128 CryptoKey from raw data
async function aes_key_gen(raw) {
    raw = new Uint8Array(raw);
    return await crypto.subtle.importKey("raw", raw, "AES-CBC", false, ["encrypt"]);
}

// encode single block "vec" and return it
async function aes_ecb(key, vec) {
    const plaintext = new Uint8Array(vec);
    const zero_iv = new Uint8Array(aes_blocksize);
    const ciphertext = await crypto.subtle.encrypt({name: "AES-CBC", iv: zero_iv}, key, plaintext);
    return Array.from(new Uint8Array(ciphertext, 0, aes_blocksize));
}

// XOR vector "dst" (modified in place) with "src" and return it
function aes_xor(dst, dst_offset, src, src_offset, max_length) {
    let length = Math.min(dst.length - dst_offset, src.length - src_offset);

    if (max_length && (max_length < length)) {
	length = max_length;
    }

    for (let i = 0; i < length; ++i) {
	dst[i + dst_offset] ^= src[i + src_offset];
    }

    return dst;
}

// encrypt "data" using OFB mode and return it
async function aes_ofb_encrypt(key, iv, data) {
    data = Array.from(data);
    let ofb = iv;

    for (let offset = 0; offset < data.length; offset += aes_blocksize) {
	ofb = await aes_ecb(key, ofb);
	aes_xor(data, offset, ofb, 0);
    }

    return data;
}

// return CBC-MAC of "data"
async function aes_cbc_mac(key, data) {
    let mac = aes_block(0);

    for (let offset = 0; offset < data.length; offset += aes_blocksize) {
	aes_xor(mac, 0, data, offset);
	mac = await aes_ecb(key, mac);
    }

    return mac;
}

// return AES-CMAC of "data"
async function aes_cmac(key, data) {
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
    return await aes_cbc_mac(key, data);
}

// return CCM-MAC computed from "aad" and "data"
async function aes_ccm_mac(key, nonce, aad, data, M = 8, L = 2) {
    const auth_flags = 0x40 /* Adata */ + (((M - 2) / 2) << 3) + (L - 1);
    const auth_data = [auth_flags, nonce, encode_msb_first(data.length, L),
		       encode_msb_first(aad.length, 2), aad, aes_padding(aad.length + 2),
		       data, aes_padding(data.length)].flat();
    const T = await aes_cbc_mac(key, auth_data);
    const enc_flags = L - 1;

    aes_xor(T, 0, await aes_ecb(key, [enc_flags, nonce, encode_msb_first(0, L)].flat()), 0);
    return T.slice(0, M);
}

// CCM encrypt / decrypt "data"
async function aes_ccm_encrypt(key, nonce, data, L = 2) {
    data = Array.from(data);
    const enc_flags = L - 1;

    for (let offset = 0; offset < data.length; offset += aes_blocksize) {
	const A = [enc_flags, nonce, encode_msb_first((offset / aes_blocksize) + 1, L)].flat();
	aes_xor(data, offset, await aes_ecb(key, A), 0);
    }

    return data;
}

// CTR_DRBG random number generator
class aes_ctr_drbg {
    async init(seed) {
	this.K = await aes_key_gen(aes_block(0));
	this.V = aes_block(0);
	await this.update(seed);
    }

    async step() {
	let V = this.V;
	for (let i = aes_blocksize - 1; (i >= 0) && ((++V[i]) == 256); --i) V[i] = 0; // increment V
	return await aes_ecb(this.K, V);
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

	await this.update(Array(aes_blocksize * 2).fill(0))
	return data.slice(0, bytes);
    }
}

/******************************************************************************
 *     security utils                                                         *
 ******************************************************************************/

async function s0_key_gen(raw) {
    const key = await aes_key_gen(raw);
    const auth_key_raw = await aes_ecb(key, aes_block(0x55));
    const enc_key_raw = await aes_ecb(key, aes_block(0xaa));

    return {raw, auth: await aes_key_gen(auth_key_raw), enc: await aes_key_gen(enc_key_raw)}
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

    return encode_lsb_first(fdiv(a, c), 32);
}

async function s2_gen_temp_key(A_private_key, A_public_key, B_public_key) {
    const shared_secret = s2_curve25519_scalarmult(A_private_key, B_public_key);
    const constant_prk = await aes_key_gen(aes_block(0x33));
    const prk_raw = await aes_cmac(constant_prk, [shared_secret, A_public_key, B_public_key].flat());
    const prk = await aes_key_gen(prk_raw);
    const constant_te = Array(15).fill(0x88);
    const T1 = await aes_cmac(prk, [constant_te, 1].flat());
    const T2 = await aes_cmac(prk, [T1, constant_te, 2].flat());
    const T3 = await aes_cmac(prk, [T2, constant_te, 3].flat());
    return {ccm: await aes_key_gen(T1), personalization_string: [T2, T3].flat()};
}

async function s2_gen_perm_key(raw) {
    const pnk = await aes_key_gen(raw);
    const constant_nk = Array(15).fill(0x55);
    const T1 = await aes_cmac(pnk, [constant_nk, 1].flat());
    const T2 = await aes_cmac(pnk, [T1, constant_nk, 2].flat());
    const T3 = await aes_cmac(pnk, [T2, constant_nk, 3].flat());
    const T4 = await aes_cmac(pnk, [T3, constant_nk, 4].flat());
    return {raw, ccm: await aes_key_gen(T1), personalization_string: [T2, T3].flat(), key_mpan: T4};
}

class s2_span {
    constructor(key, rei) {
	this.key = key;
	this.rei = rei;
	this.drbg = new aes_ctr_drbg();
    }

    async set_sei(sei) {
	this.sei = sei;
	const constant_nonce = await aes_key_gen(aes_block(0x26));
	const nonce_prk_raw = await aes_cmac(constant_nonce, [sei, this.rei].flat());
	const nonce_prk = await aes_key_gen(nonce_prk_raw);
	const constant_ei = Array(15).fill(0x88);
	const T0 = [constant_ei, 0].flat();
	const T1 = await aes_cmac(nonce_prk, [T0, constant_ei, 1].flat());
	const T2 = await aes_cmac(nonce_prk, [T1, constant_ei, 2].flat());
	const seed = [T1, T2].flat();
	aes_xor(seed, 0, this.key.personalization_string, 0);
	await this.drbg.init(seed);
    }

    async next_nonce() {
	return (await this.drbg.gen(16)).slice(0, 13);
    }
}

/******************************************************************************
 *     security classes definitions                                           *
 ******************************************************************************/

zwave_cc_security.SECURITY = {
    id: 0x98,
    async security_init(node) {
	node.security = {
	    cc: this,
	    key: await s0_key_gen(node.z.security.s0.key),
	    temp_key: await s0_key_gen(aes_block(0)),
	    nonce: Array(256),
	    nonce_id: 0
	};

	node.recv.SECURITY_NONCE_GET = this.recv_nonce_get.bind(this, node);
    },
    async bootstrap(node) {
	if (await node.send.SECURITY_SCHEME_GET().recv.SECURITY_SCHEME_REPORT(2)) {
	    await this.security_init(node);
	    return await node.send.NETWORK_KEY_SET({key: node.security.key.raw}).recv.NETWORK_KEY_VERIFY(2);
	}
    },
    recv_nonce_get(node) {
        const nonce_id = (node.security.nonce_id + 1) % 256;
        const nonce = rand(8);
        nonce[0] = nonce_id;
        node.security.nonce[nonce_id] = nonce;
        node.security.nonce_id = nonce_id;

        // disable after 3 seconds
        setTimeout(() => {nonce.length = 0}, 3000);

	// send
	node.send.SECURITY_NONCE_REPORT({nonce});
    },
    async encapsulate(cmd) {
	if (cmd.def.no_encap) {
	    return cmd;
	}

	const node = cmd.node;
	const z = node.z;
	const key = (cmd.def == this.cmd.NETWORK_KEY_SET) ? node.security.temp_key : node.security.key;
	const nonce_report = await node.send.SECURITY_NONCE_GET().recv.SECURITY_NONCE_REPORT();

	if (!nonce_report) {
	    return "no receiver_nonce for S0 encapsulation";
	}

	const receiver_nonce = nonce_report.nonce;
	return await node.gen.SECURITY_MESSAGE_ENCAPSULATION({cmd, key, receiver_nonce});
    },
    cmd: {
	SECURITY_SCHEME_GET: {id: 0x04, encode_fmt: {supported: 1}},
	SECURITY_SCHEME_REPORT: {id: 0x05, decode_fmt: {supported: 1}},
	NETWORK_KEY_SET: {id: 0x06, encode_fmt: {key: 16}},
	NETWORK_KEY_VERIFY: {id: 0x07, decode_fmt: {}},
	SECURITY_NONCE_GET: {id: 0x40, no_encap: true, fmt: {}},
	SECURITY_NONCE_REPORT: {id: 0x80, no_encap: true, fmt: {nonce: 8}},
	SECURITY_MESSAGE_ENCAPSULATION: {
	    id: 0x81,
	    async encode(cmd) {
		// encrypt
		const decrypted_pld = [0 /* seq_info */, cmd.args.cmd.id, cmd.args.cmd.pld ?? []].flat(10);
		const sender_nonce = rand(8);
		const receiver_nonce = cmd.args.receiver_nonce;
		const iv = sender_nonce.concat(receiver_nonce);
		const encrypted_pld = await aes_ofb_encrypt(cmd.args.key.enc, iv, decrypted_pld);

		// authentication code
		const auth_data = [sender_nonce, receiver_nonce, cmd.id[1],
				   cmd.node.z.nodeid, cmd.node.nodeid, encrypted_pld.length, encrypted_pld].flat();
		const mac = (await aes_cbc_mac(cmd.args.key.auth, auth_data)).slice(0, 8);

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
		const receiver_nonce = cmd.node.security.nonce[receiver_nonce_id];

		if (!receiver_nonce) {
		    cmd.msg.push("no receiver nonce:" + receiver_nonce_id);
		    return;
		}

		delete cmd.node.security.nonce[receiver_nonce_id];

		if (receiver_nonce.length < 8) {
		    cmd.msg.push("receiver nonce expired");
		    return;
		}

		// authentication code check
		const key = cmd.node.security.key;
		const auth_data = [sender_nonce, receiver_nonce, cmd.id[1], cmd.node.nodeid, cmd.node.z.nodeid,
				   encrypted_pld_len, encrypted_pld].flat();
		const expected_mac = (await aes_cbc_mac(key.auth, auth_data)).slice(0, 8);

		if (mac.toString() != expected_mac.toString()) {
		    cmd.msg.push("incorrect MAC");
		    return;
		}

		// decrypt
		const decrypted_pld = await aes_ofb_encrypt(key.enc, sender_nonce.concat(receiver_nonce), encrypted_pld);

		// check seq info
		const seq_info = decrypted_pld[0];

		if (seq_info != 0) {
		    cmd.msg.push("unexpected sequence byte:" + seq_info);
		    return;
		}

		// extract encapsulated cmd
		cmd.args = {cmd: {id: decrypted_pld.slice(1, 3), pld: decrypted_pld.slice(3)}};
		cmd.msg.push("|");
	    }
	}
    }
};

zwave_cc_security.SECURITY_2 = {
    id: 0x9f,
    async security_init(node, subtype) {
	node.security = {
	    cc: this,
	    key: await s2_gen_perm_key(node.z.security.s2[subtype].key),
	    send_seq: rand(1)[0],
	    recv_seq: 256
	};

	node.recv.SECURITY_2_NONCE_GET = this.recv_nonce_get.bind(this, node);
	node.recv.SECURITY_2_NONCE_REPORT = this.recv_nonce_report.bind(this, node);
    },
    async bootstrap(node, dsk = []) {
	// check dsk
	if (typeof(dsk) == "number") {
	    dsk = encode_msb_first(dsk, 2);
	}

	if (![0, 2, 16].includes(dsk.length)) {
	    return "wrong dsk length";
	}

	// get capabilities
	const kex_report = await node.send.KEX_GET().recv.KEX_REPORT(10);

	if (!kex_report || (kex_report.flags & 1) /* echo set */ ||
	    !(kex_report.supported_schemes & 0x2) || !(kex_report.supported_profiles & 0x1)) {
	    return "bad KEX_REPORT";
	}

	// grant highest level key
	for (let i = (dsk.length > 0) ? 2 : 0; i >= 0; --i) {
	    if (kex_report.requested_keys & (1 << i)) {
		// only grant highest level key
		var granted_key = 1 << i;
		var subtype = i;
		break;
	    }
	}

	if (!granted_key) {
	    return "could not grant any keys";
	}

	// get peer public key
	const public_key_report = await node
	      .send.KEX_SET({flags: kex_report.flags & 2 /* approve CSA if requested */,
			     selected_scheme: 2, selected_profile: 1, granted_keys: granted_key})
	      .recv.PUBLIC_KEY_REPORT(10);

	if (!public_key_report || (public_key_report.including_node != 0)) {
	    return "no valid public key received";
	}

	const B_public_key = [dsk, public_key_report.public_key.slice(dsk.length)].flat();

	// enable encryption and save permanent key for later
	await this.security_init(node, subtype);
	const perm_key = node.security.key;

	// generate our private/public key and setup temporary key
	const A_private_key = rand(32);
	const A_public_key = s2_curve25519_scalarmult(A_private_key, [9]);
	const temp_key = await s2_gen_temp_key(A_private_key, A_public_key, B_public_key);
	node.security.key = temp_key;

	// send our public key and establish temporary SPAN
	const kex_set_echo = await node
	      .send.PUBLIC_KEY_REPORT({including_node: 1, public_key: A_public_key})
	      .recv.KEX_SET(10);

	if (!kex_set_echo || !(kex_set_echo.flags & 1) /* echo not set */ ||
	    (kex_set_echo.granted_keys != granted_key)) {
	    return "bad KEX_SET";
	}

	// start network key transfer
	kex_report.flags |= 1; // echo

	const network_key_get = await node
	      .send.KEX_REPORT(kex_report)
	      .recv.SECURITY_2_NETWORK_KEY_GET(10);

	if (!network_key_get || (network_key_get.requested_key != granted_key)) {
	    return "bad NETWORK_KEY_GET";
	}

	// send and verify network key
	node.security.key = perm_key; // SPAN will get reset on the next received NONCE_GET
	const network_key_verify = await node
	      .send.SECURITY_2_NETWORK_KEY_REPORT({granted_key, network_key: perm_key.raw})
	      .recv.SECURITY_2_NETWORK_KEY_VERIFY(10);

	if (!network_key_verify) {
	    return "no NETWORK_KEY_VERIFY";
	}

	// final handshake using temporary key
	node.security.key = temp_key;
	delete node.security.span; // to generate a new span on the send
	const transfer_end = await node
	      .send.SECURITY_2_TRANSFER_END({flags: 2})
	      .recv.SECURITY_2_TRANSFER_END(10);

	if (!transfer_end || (transfer_end.flags != 1)) {
	    return "bad TRANSFER_END";
	}

	// success! switch back to permanent key
	node.security.key = perm_key;
	delete node.security.span;

	console.log("S2 bootstrap for node " + node.nodeid + " completed!");
	return true;
    },
    recv_nonce_get(node) {
	const rei = rand(16);
	node.security.span = new s2_span(node.security.key, rei);
	node.send.SECURITY_2_NONCE_REPORT({rei});
    },
    recv_nonce_report(node, args) {
	node.security.span = new s2_span(node.security.key, args.rei);
    },
    check_recv_seq(cmd) {
	if (cmd.pld.length == 0) {
	    cmd.msg.push("bad encoding");
	} else if (cmd.pld[0] == cmd.node.security.recv_seq) {
	    cmd.msg.push("duplicate");
	} else {
	    cmd.node.security.recv_seq = cmd.pld[0];
	    return true;
	}
    },
    async encapsulate(cmd) {
	if (cmd.def.no_encap) {
	    return cmd;
	}

	const node = cmd.node;

	if (!node.security.span) {
	    const nonce_report = await node.send.SECURITY_2_NONCE_GET().recv.SECURITY_2_NONCE_REPORT();

	    if (!nonce_report) {
		return "no SPAN for S2 encapsulation";
	    }

	    node.security.span = new s2_span(node.security.key, nonce_report.rei);
	}

	return await node.gen.SECURITY_2_MESSAGE_ENCAPSULATION({cmd});
    },
    cmd: {
	SECURITY_2_NONCE_GET: {
	    id: 0x01,
	    no_encap: true,
	    encode(cmd) {
		cmd.pld = [cmd.node.security.send_seq++];
	    },
	    decode(cmd) {
		if (zwave_cc_security.SECURITY_2.check_recv_seq(cmd)) {
		    if (cmd.pld.length == 1) {
			cmd.args = {}
		    } else {
			cmd.msg.push("bad encoding");
		    }
		}
	    }
	},
	SECURITY_2_NONCE_REPORT: {
	    id: 0x02,
	    no_encap: true,
	    encode(cmd) {
		cmd.pld = [cmd.node.security.send_seq++, 1, cmd.args.rei].flat();
		cmd.msg.push("SOS");
	    },
	    decode(cmd) {
		if (zwave_cc_security.SECURITY_2.check_recv_seq(cmd)) {
		    if ((cmd.pld.length == 18) && (cmd.pld[1] == 1)) {
			cmd.args = {rei: cmd.pld.slice(2)}
			cmd.msg.push("SOS");
		    } else if ((cmd.pld.length == 2) && (cmd.pld[1] == 2)) {
			cmd.msg.push("MOS (unsupported)");
		    } else {
			cmd.msg.push("bad encoding");
		    }
		}
	    }
	},
	SECURITY_2_MESSAGE_ENCAPSULATION: {
	    id: 0x03,
	    async encode(cmd) {
		const node = cmd.node;
		const z = node.z;

		// generate nonce and optional SEI extension
		const span = node.security.span;
		const key_ccm = span.key.ccm;
		let ext = [0];

		if (!span.sei) {
		    cmd.msg.push("+ SEI");
		    await span.set_sei(rand(16));
		    ext = [1 /* include ext */, 18, 0x41 /* SPAN type + critical */, span.sei].flat();
		}

		const nonce = await span.next_nonce();

		// encrypt
		const decrypted_pld = [cmd.args.cmd.id, cmd.args.cmd.pld ?? []].flat(10);
		const encrypted_pld = await aes_ccm_encrypt(key_ccm, nonce, decrypted_pld);

		// authenticate
		const seq = node.security.send_seq++;
		const msg_length = 3 + ext.length + decrypted_pld.length + 8 /* MAC */;
		const aad = [z.nodeid, node.nodeid, z.home_id, encode_msb_first(msg_length, 2), seq, ext].flat();
		const mac = await aes_ccm_mac(key_ccm, nonce, aad, decrypted_pld);

		// encapsulate
		cmd.pld = [seq, ext, encrypted_pld, mac];
		cmd.msg.push("|", ...cmd.args.cmd.msg);
	    },
	    async decode(cmd) {
		if (!zwave_cc_security.SECURITY_2.check_recv_seq(cmd)) {
		    return;
		}

		const pld = cmd.pld;

		if (pld.length < 2) {
		    cmd.msg.push("bad encoding");
		    return;
		}

		const node = cmd.node;
		const span = node.security.span;

		if (!span) {
		    zwave_cc_security.SECURITY_2.recv_nonce_get(node);
		    cmd.msg.push("no SPAN");
		    return;
		}

		const z = node.z;
		const key_ccm = span.key.ccm;
		const seq = pld[0];
		const msg_length = pld.length + 2;
		let sei = false;

		// parse extensions
		let has_ext = pld[1] & 1;
		let ext_offset = 2;

		while (has_ext) {
		    const ext_length = pld[ext_offset];

		    if ((ext_length < 2) || ((ext_offset + ext_length) > pld.length)) {
			cmd.msg.push("bad encoding (parsing ext)");
			return;
		    }

		    const ext_type_critical = pld[ext_offset + 1] & 0x7f;

		    if ((ext_type_critical == 0x41) && (ext_length == 18)) {
			sei = pld.slice(ext_offset + 2, ext_offset + 18);
			cmd.msg.push("+ SEI");

			if (span.sei) {
			    zwave_cc_security.SECURITY_2.recv_nonce_get(node);
			    cmd.msg.push("SPAN already initialized");
			    return;
			}

			await span.set_sei(sei);
		    }

		    has_ext = pld[ext_offset + 1] & 0x80;
		    ext_offset += ext_length;
		}

		const ext = pld.slice(1, ext_offset);

		// check that we have a valid SPAN
		if (!span.sei) {
		    zwave_cc_security.SECURITY_2.recv_nonce_get(node);
		    cmd.msg.push("SPAN not fully initialized");
		    return;
		}

		// check ciphertext minimum length (MAC + command id)
		const ciphertext = pld.slice(ext_offset);

		if (ciphertext.length < 10) {
		    cmd.msg.push("bad encoding (ciphertext length)");
		    return;
		}

		// decrypt
		const encrypted_pld = ciphertext.slice(0, ciphertext.length - 8);
		const mac = ciphertext.slice(ciphertext.length - 8);
		const aad = [node.nodeid, z.nodeid, z.home_id, encode_msb_first(msg_length, 2), seq, ext].flat();

		for (let i = 0; i < 5; ++i) {
		    const nonce = await span.next_nonce();
		    var decrypted_pld = await aes_ccm_encrypt(key_ccm, nonce, encrypted_pld);
		    const expected_mac = await aes_ccm_mac(key_ccm, nonce, aad, decrypted_pld);

		    if (mac.toString() == expected_mac.toString()) {
			break;
		    } else if (i == 4) {
			zwave_cc_security.SECURITY_2.recv_nonce_get(node);
			cmd.msg.push("could not decrypt with current SPAN");
			return;
		    }
		}

		// parse encrypted extensions (we ignore as multicast not supported)
		has_ext = pld[1] & 2;
		ext_offset = 0;

		while (has_ext) {
		    const ext_length = decrypted_pld[ext_offset];

		    if ((ext_length < 2) || ((ext_offset + ext_length) > decrypted_pld.length)) {
			cmd.msg.push("bad encoding (parsing encrypted ext)");
			return;
		    }

		    has_ext = decrypted_pld[ext_offset + 1] & 0x80;
		    ext_offset += ext_length;
		}

		// extract encapsulated cmd
		const encapsulated_cmd = decrypted_pld.slice(ext_offset);

		if (encapsulated_cmd.length < 2) {
		    cmd.msg.push("no valid cmd after encrypted ext");
		    return;
		}

		cmd.args = {cmd: {id: encapsulated_cmd.slice(0, 2), pld: encapsulated_cmd.slice(2)}};
		cmd.msg.push("|");
	    }
	},
	KEX_GET: {id: 0x04, encode_fmt: {}},
	KEX_REPORT: {id: 0x05, fmt: {flags:1, supported_schemes: 1, supported_profiles: 1, requested_keys: 1}},
	KEX_SET: {id: 0x06, fmt: {flags:1, selected_scheme: 1, selected_profile: 1, granted_keys: 1}},
	KEX_FAIL: {id: 0x07, fmt: {type: 1}},
	PUBLIC_KEY_REPORT: {id: 0x08, no_encap: true, fmt: {including_node: 1, public_key: 32}},
	SECURITY_2_NETWORK_KEY_GET: {id: 0x09, decode_fmt: {requested_key: 1}},
	SECURITY_2_NETWORK_KEY_REPORT: {id: 0x0a, encode_fmt: {granted_key: 1, network_key: 16}},
	SECURITY_2_NETWORK_KEY_VERIFY: {id: 0x0b, decode_fmt: {}},
	SECURITY_2_TRANSFER_END: {id: 0x0c, fmt: {flags: 1}},
	SECURITY_2_COMMANDS_SUPPORTED_GET: {id: 0x0d, encode_fmt: {}},
	SECURITY_2_COMMANDS_SUPPORTED_REPORT: {id: 0x0e, decode_fmt: {cc_list: 0}}
    }
};
