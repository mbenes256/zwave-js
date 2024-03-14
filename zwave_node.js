import {async_mutex, hex_bytes} from "./zwave_utils.js"
import {zwave_cc} from "./zwave_cc.js"

/*
 * This class handles sending and receiving commands to a specific node according to the command class definitions
 */

export class zwave_node {
    constructor(z, nodeid) {
	this.z = z;
	this.nodeid = nodeid;
	this.mutex = new async_mutex();

	// gen proxy
	this.gen = new Proxy(this, zwave_node.gen_proxy_handler);

	// this object will be populated with receive callbacks
	this.recv = {
	    _ep: [],
	    ep(epid) {
		if (!this._ep[epid]) {
		    this._ep[epid] = {};
		}
		return this._ep[epid];
	    }
	};
    }

    static gen_proxy_handler = {
	get(node, cmd_name) {
	    const cmd_def = zwave_cc._cmd_name_map.get(cmd_name);

	    if (cmd_def?.encode) {
		const cmd = node.new_cmd(cmd_def);
		return async function (args) {
		    cmd.args = args;
		    await cmd_def.encode(cmd);
		    return cmd;
		}
	    }
	}
    }

    get send() {
	const send = {
	    node: this,
	    ep(epid) {this.epid = epid; return this.proxy}
	};

	send.proxy = new Proxy(send, zwave_node.send_proxy_handler);
	return send.proxy;
    }

    static send_proxy_handler = {
	get(send, cmd_name) {
	    const cmd_def = zwave_cc._cmd_name_map.get(cmd_name);

	    if (cmd_def?.encode) {
		const cmd = send.node.new_cmd(cmd_def, send.epid);

		return function (args = {}) {
		    cmd.args = args;
		    const promise = send.node.run_cmd(cmd);
		    const recv = {promise, cmd};
		    // return the async function promise, but allow cmd modification using recv_proxy_handler
		    promise.recv = new Proxy(recv, zwave_node.recv_proxy_handler);
		    return promise;
		};
	    }

	    // default to support node, ep, s0 properties
	    return Reflect.get(...arguments);
	}
    }

    static recv_proxy_handler = {
	get(recv, property) {
	    const cmd_def = zwave_cc._cmd_name_map.get(property);

	    if (cmd_def?.decode) {
		recv.cmd.recv_cmd_def = cmd_def;
		return function (timeout = 1) {
		    recv.cmd.recv_timeout = timeout;
		    return recv.promise;
		}
	    }
	}
    };

    new_cmd(cmd_def, epid) {
	return {
	    node: this,
	    def: cmd_def,
	    id: [cmd_def.cc_id, cmd_def.id],
	    msg: [cmd_def.name],
	    epid: epid
	}
    }

    async run_cmd(cmd) {
	// this await also allows cmd modification using recv_proxy_handler before we continue
	await cmd.def.encode(cmd);
	const cmd_orig = cmd;

	// encapsulate
	if (cmd_orig.epid > 0) {
	    cmd = await zwave_cc.MULTI_CHANNEL.encapsulate(cmd);
	}

	if (this.security) {
	    cmd = await this.security.cc.encapsulate(cmd);

	    if (typeof(cmd) == "string") {
		return this.error(cmd, cmd_orig);
	    }
	}

	// send to node only
	if (!cmd_orig.recv_cmd_def) {
	    return await this.z.bridge_node_send(cmd);
	}

	// send/recv flow
	await this.mutex.lock();
	this.cmd_current = cmd_orig;
	const result = await this.send_recv_cmd(cmd);
	delete this.cmd_current;
	this.mutex.unlock();

	if (typeof(result) == "string") {
	    return this.error(result, cmd_orig);
	}

	return result;
    }

    error(msg, cmd) {
	this.z.log_func("ERROR:", msg, "| node:" + this.nodeid, ...cmd.msg);
	this.z.log_func();
	return false;
    }

    async send_recv_cmd(cmd) {
	// retrieve original non-encapsulated command
	const cmd_orig = this.cmd_current;

	// setup promise for response or error
	const promise = new Promise((resolve) => {cmd_orig.resolve = resolve});

	// send request
	if (!await this.z.bridge_node_send(cmd)) {
	    cmd_orig.resolve("send failed");
	}

	// start timer
	const cmd_timeout = setTimeout(cmd_orig.resolve.bind(null, "timeout"), 1000 * (cmd_orig.recv_timeout ?? 1));

	// wait for response (args object) or error (string)
	const result = await promise;
	clearTimeout(cmd_timeout);
	return result;
    }

    async recv_cmd(cmd) {
	cmd.node = this;

	while (true) {
	    // decode
	    var cmd_def = zwave_cc._cc_id_map.get(cmd.id[0])?._cmd_id_map.get(cmd.id[1]);

	    if (!cmd_def?.decode) {
		cmd.msg.push("unsupported command for receive:", hex_bytes(cmd.id));
		return;
	    }

	    cmd.msg.push(cmd_def.name);
	    await cmd_def.decode(cmd);

	    if (!cmd.args) {
		return;
	    }

	    if (!cmd.args.cmd) {
		// not encapuslated
		break;
	    }

	    // encapsulated - replace id/pld and repeat
	    cmd.id = cmd.args.cmd.id;
	    cmd.pld = cmd.args.cmd.pld;
	    delete cmd.args;
	}

	// check if should be secure
	if (this.security && !cmd_def.no_encap && !cmd.secure) {
	    cmd.msg.push("(not secure - ignored)");
	    return;
	}

	// check if this matches an expected command
	const cmd_current = this.cmd_current;

	if (cmd_current && (cmd_current.recv_cmd_def == cmd_def) && (cmd_current.epid == cmd.epid)) {
	    cmd_current.resolve(cmd.args);
	} else {
	    // user callback
	    let recv = cmd.epid ? this.recv.ep(cmd.epid) : this.recv;
	    recv[cmd_def.name]?.(cmd.args);
	}
    }
}
