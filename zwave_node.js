import {async_mutex} from "./zwave_utils.js"
import {zwave_cc} from "./zwave_cc.js"

/*
 * This class handles sending and receiving commands to a specific node according to the command class definitions
 */

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
	    id: [cmd_def.cc_id, cmd_def.id],
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
	const cmd_timeout = setTimeout(cmd_orig.report.bind(null, "timeout"), 1000 * (cmd_orig.timeout ?? 1));
	const report = await report_promise;
	clearTimeout(cmd_timeout);
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
