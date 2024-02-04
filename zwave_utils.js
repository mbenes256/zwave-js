
// wait for "ms" milliseconds
export async function sleep(ms) {
    await new Promise((resolve) => {
        setTimeout(() => resolve(), ms);
    });
}

// return the key string for the properety of "obj" that has value "val"
export function obj_val_key(obj, val) {
    for (let e of Object.entries(obj)) {
	if (e[1] == val) {
	    return e[0];
	}
    }

    return obj._default;
}

// return a lit of bits set in the array of bytes "arr"; the lsb of the first byte is index "index"
export function get_bit_list(arr, index = 0) {
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

// convert an array of bytes into BigInt, assuming little endian order (first byte is LSB)
export function bigint_from_array(arr) {
    let n = 0n;
    // little endian
    for (let i = arr.length - 1; i >= 0; --i) {
	n = (n << 8n) | BigInt(arr[i]);
    }
    return n;
}

// convert a number or BigInt "n" into array of length "bytes", assuming little endian order (first byte is LSB)
export function encode_lsb_first(n, bytes) {
    const arr = [];
    n = BigInt(n);

    while ((bytes--) > 0) {
	arr.push(Number(n & 0xffn))
	n >>= 8n;
    }

    return arr;
}

// convert a number or BigInt "n" into array of length "bytes", assuming big endian order (first byte is MSB)
export function encode_msb_first(n, bytes) {
    return encode_lsb_first(n, bytes).reverse();
}

// convert array of bytes to a string with 2-digit hex representation for each byte, separated by spaces
export function hex_bytes(arr) {
    return arr.map((e) => (e & 0xff).toString(16).padStart(2, "0")).join(" ");
}

// convert an arbitrary hex string to array of bytes (spaces allowed between hex bytes)
export function array_from_hex(str) {
    return str.match(/[0-9a-fA-F]{2}/g).map((s) => Number.parseInt(s, 16));
}

// convert "args" object properties into an array of bytes, given a format definition "fmt"
export function pack_fmt(args, fmt) {
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

// convert an array of bytes "arr", given a format definition "fmt", into an object with properties
export function unpack_fmt(arr, fmt) {
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

// convert "args" object properties into an string, given a format definition "fmt"
export function print_fmt(args, fmt) {
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

// a mutex object that grants lock in the order of requested
export class async_mutex {
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

// return an array of random bytes or length "bytes"
export function rand(bytes) {
    const buf = new Uint8Array(bytes);
    crypto.getRandomValues(buf);
    return Array.from(buf);
}
