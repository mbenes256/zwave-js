import {rand} from "./zwave_utils.js"

export const zwave_cc_security = {};

/******************************************************************************
 *     AES utils                                                              *
 ******************************************************************************/

// - all functions assume AES-128
// - all buffers are Arrays of Numbers (each element represents a single byte)
// - resulting buffers modified in place and returned

const aes_blocksize = 16;

// gnerate a block with constant value "val"
export function aes_block(val) {
    return Array(aes_blocksize).fill(val);
}

// generate an array of padding required to append to an array of "current_length" to read multiple of block size
function aes_padding(current_length, val = 0) {
    const len = (aes_blocksize - (current_length % aes_block_size)) % aes_block_size;
    return Array(len).fill(val);
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

export async function s0_key_gen(network_key_raw) {
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
 *     security classes definitions                                           *
 ******************************************************************************/

zwave_cc_security.SECURITY = {
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

zwave_cc_security.SECURITY_2 = {
    id: 0x9f,
    cmd: {
	SECURITY_2_NONCE_GET: {id: 0x01},
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
