/*
 * Basic command classes definitions
 */

export const zwave_cc_basic = {};

zwave_cc_basic.BINARY_SWITCH = {
    id: 0x25,
    cmd: {
	SWITCH_BINARY_SET: {id: 0x01, encode_fmt: {value: 1}},
	SWITCH_BINARY_GET: {id: 0x02, encode_fmt: {}, report_cmd: "SWITCH_BINARY_REPORT"},
	SWITCH_BINARY_REPORT: {id: 0x03, decode_fmt: [{value: 1, target: 1, duration: 1}, {value: 1}]}
    }
};

zwave_cc_basic.BINARY_SENSOR = {
    id: 0x30,
    cmd: {
	SENSOR_BINARY_REPORT: {id: 0x03, decode_fmt: [{value: 1, type: 1}, {value: 1}]}
    }
};

zwave_cc_basic.CONFIGURATION = {
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

zwave_cc_basic.BATTERY = {
    id: 0x80,
    cmd: {
	BATTERY_GET: {id: 0x02, encode_fmt: {}, report_cmd: "BATTERY_REPORT"},
	BATTERY_REPORT: {id: 0x03, decode_fmt: [{level: 1, flags: 2}, {level: 1}]}
    }
};

zwave_cc_basic.NOTIFICATION = {
    id: 0x71,
    cmd: {
	NOTIFICATION_REPORT: {id: 0x05, decode_fmt: {__unused1: 4, type: 1, state: 1, __unused2: 0}}
    }
};

zwave_cc_basic.WAKE_UP = {
    id: 0x84,
    cmd: {
	WAKE_UP_NOTIFICATION: {id: 0x07, decode_fmt: {}}
    }
};

zwave_cc_basic.MULTI_CHANNEL = {
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
