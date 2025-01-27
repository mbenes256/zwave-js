/*
 * Basic command classes definitions
 */

export const zwave_cc_basic = {};

zwave_cc_basic.BASIC = {
    id: 0x20,
    cmd: {
	BASIC_SET: {id: 0x01, fmt: {value: 1}},
	BASIC_GET: {id: 0x02, encode_fmt: {}},
	BASIC_REPORT: {id: 0x03, decode_fmt: [{value: 1, target: 1, duration: 1}, {value: 1}]}
    }
};

zwave_cc_basic.SWITCH_BINARY = {
    id: 0x25,
    cmd: {
	SWITCH_BINARY_SET: {id: 0x01, encode_fmt: {value: 1}},
	SWITCH_BINARY_GET: {id: 0x02, encode_fmt: {}},
	SWITCH_BINARY_REPORT: {id: 0x03, decode_fmt: [{value: 1, target: 1, duration: 1}, {value: 1}]}
    }
};

zwave_cc_basic.SENSOR_BINARY = {
    id: 0x30,
    cmd: {
	SENSOR_BINARY_GET: {id: 0x02, encode_fmt: {}},
	SENSOR_BINARY_REPORT: {id: 0x03, decode_fmt: [{value: 1, type: 1}, {value: 1}]}
    }
};

zwave_cc_basic.SENSOR_MULTILEVEL = {
    id: 0x31,
    cmd: {
	SENSOR_MULTILEVEL_SUPPORTED_GET_SENSOR: {id: 0x01, encode_fmt: {}},
	SENSOR_MULTILEVEL_SUPPORTED_SENSOR_REPORT: {id: 0x02, decode_fmt: {bit_mask: 0}},
	SENSOR_MULTILEVEL_SUPPORTED_GET_SCALE: {id: 0x03, encode_fmt: {type: 1}},
	SENSOR_MULTILEVEL_GET: {id: 0x04, encode_fmt: {type: 1, scale_bit_mask: 1}},
	SENSOR_MULTILEVEL_REPORT: {
	    id: 0x05,
	    decode(cmd) {
		if (cmd.pld.length < 3) {
		    cmd.msg.push("bad encoding");
		    return;
		}

		const type = cmd.pld[0];
		const size = cmd.pld[1] & 0x7;
		const scale = (cmd.pld[1] >> 3) & 0x3;
		const precision = cmd.pld[1] >> 5;
		const dv = new DataView((new Uint8Array(cmd.pld.slice(2))).buffer);
		let value;

		if (size <= dv.byteLength) {
		    if (size == 1) {
			value = dv.getInt8(0);
		    } else if (size == 2) {
			value = dv.getInt16(0);
		    } else if (size == 4) {
			value = dv.getInt32(0);
		    }
		}

		if (value != undefined) {
		    value /= Math.pow(10, precision);
		    cmd.args = {type, scale, value};
		    cmd.msg.push("type:" + type, "scale:" + scale, "value:" + value);
		} else {
		    cmd.msg.push("bad encoding");
		}
	    }
	}
    }
};

zwave_cc_basic.ASSOCIATION_GRP_INFO = {
    id: 0x59,
    cmd: {
	ASSOCIATION_GROUP_NAME_GET: {id: 0x01, fmt: {}},
	ASSOCIATION_GROUP_NAME_REPORT: {id: 0x02, fmt: {}},
	ASSOCIATION_GROUP_INFO_GET: {id: 0x03, fmt: {flags: 1, group: 1}},
	ASSOCIATION_GROUP_INFO_REPORT: {id: 0x04, fmt: {count: 1, grpup: 1, info: 6}},
	ASSOCIATION_GROUP_COMMAND_LIST_GET: {id: 0x05, fmt: {flags: 1, group: 1}},
	ASSOCIATION_GROUP_COMMAND_LIST_REPORT: {id: 0x06, fmt: {grpup: 1, length: 1, cmds: 0}}
    }
}

zwave_cc_basic.CENTRAL_SCENE = {
    id: 0x5b,
    cmd: {
	CENTRAL_SCENE_SUPPORTED_GET: {id: 0x01, fmt: {}},
	CENTRAL_SCENE_SUPPORTED_REPORT: {id: 0x02, fmt: {}},
	CENTRAL_SCENE_NOTIFICATION: {id: 0x03, decode_fmt: {seq_num: 1, key_attr: 1, scene_num: 1}},
	CENTRAL_SCENE_CONFIGURATION_SET: {id: 0x04, fmt: {}},
	CENTRAL_SCENE_CONFIGURATION_GET: {id: 0x05, fmt: {}},
	CENTRAL_SCENE_CONFIGURATION_REPORT: {id: 0x06, fmt: {}}
    }
};

zwave_cc_basic.ZWAVEPLUS_INFO = {
    id: 0x5e,
    cmd: {
	ZWAVEPLUS_INFO_GET: {id: 0x01, encode_fmt: {}},
	ZWAVEPLUS_INFO_REPORT: {id: 0x02, decode_fmt: [{info: 0}]}
    }
};

zwave_cc_basic.MULTI_CHANNEL = {
    id: 0x60,
    async encapsulate(cmd) {
	return await cmd.node.gen.MULTI_CHANNEL_CMD_ENCAP({cmd});
    },
    cmd: {
	MULTI_CHANNEL_END_POINT_GET: {id: 0x07, encode_fmt: {}},
	MULTI_CHANNEL_END_POINT_REPORT: {id: 0x08, decode_fmt:
					 [{flags: 1, end_points: 1},
					  {flags: 1, individual_end_points: 1, aggregated_end_poins: 1}]},
	MULTI_CHANNEL_CAPABILITY_GET: {id: 0x09, encode_fmt: {epid: 1}},
	MULTI_CHANNEL_CAPABILITY_REPORT: {
	    id: 0x0a, decode_fmt: {epid: 1, generic_class:1, specific_class: 1, cc_list: 0}},
	MULTI_CHANNEL_CMD_ENCAP: {
	    id: 0x0d,
	    encode(cmd) {
		cmd.pld = [0, cmd.args.cmd.epid, cmd.args.cmd.id, cmd.args.cmd.pld];
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

zwave_cc_basic.SUPERVISION = {
    id: 0x6c,
    cmd: {
	SUPERVISION_GET: {
	    id: 0x01,
	    decode(cmd) {
		if ((cmd.pld.length < 4) || ((cmd.pld[1] + 2) != cmd.pld.length)) {
		    cmd.msg.push("bad encoding");
		    return;
		}

		const session = cmd.pld[0] & 0x3f;
		cmd.node.send.SUPERVISION_REPORT({session, status: 0xff, duration: 0});

		/* ignore for now since sometimes we see duplicate session for legit new commands
		if (!cmd.node.supervision) {
		    cmd.node.supervision = {last_session: 256};
		}

		if (session == cmd.node.supervision.last_session) {
		    cmd.msg.push("duplicate");
		    return;
		}

		cmd.node.supervision.last_session = session;
		*/

		cmd.args = {cmd: {id: cmd.pld.slice(2, 4), pld: cmd.pld.slice(4)}};
		cmd.msg.push("session:" + session, "|");
	    }
	},
	SUPERVISION_REPORT: {id: 0x02, fmt: {session: 1, status:1, duration: 1}}
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

		cmd.pld = [param, size, Array.from(val_buf)];
		cmd.msg.push("param:" + param, "size:" + size, "value:" + value);
	    }
	},
	CONFIGURATION_GET: {id: 0x05, encode_fmt: {param: 1}},
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

zwave_cc_basic.NOTIFICATION = {
    id: 0x71,
    cmd: {
	EVENT_SUPPORTED_GET: {id: 0x01, encode_fmt: {type: 1}},
	EVENT_SUPPORTED_REPORT: {id: 0x02, decode_fmt: {type: 1, mask_bytes: 1, mask: 0}},
	NOTIFICATION_GET: {id: 0x04, encode_fmt: {alarm: 1, type: 1, event: 1}},
	NOTIFICATION_REPORT: {id: 0x05, decode_fmt: {__unused1: 4, type: 1, state: 1, __unused2: 0}},
	NOTIFICATION_SET : {id: 0x06, encode_fmt: {type: 1, status: 1}},
	NOTIFICATION_SUPPORTED_GET: {id: 0x07, encode_fmt: {}},
	NOTIFICATION_SUPPORTED_REPORT: {id: 0x08, decode_fmt: {mask_bytes: 1, mask: 0}}
    }
};

zwave_cc_basic.MANUFACTURER_SPECIFIC = {
    id: 0x72,
    cmd: {
	MANUFACTURER_SPECIFIC_GET: {id: 0x04, encode_fmt: {}},
	MANUFACTURER_SPECIFIC_REPORT: {id: 0x05, decode_fmt: {info: 0}},
	DEVICE_SPECIFIC_GET: {id: 0x06, encode_fmt: {}},
	DEVICE_SPECIFIC_REPORT: {id: 0x07, decode_fmt: {info: 0}}
    }
};

zwave_cc_basic.FIRMWARE_UPDATE_MD = {
    id: 0x7a,
    cmd: {
	FIRMWARE_MD_GET: {id: 0x01, encode_fmt: {}},
	FIRMWARE_MD_REPORT: {id: 0x02, decode_fmt: {info: 0}},
	FIRMWARE_UPDATE_MD_REQUEST_GET: {id: 0x03},
	FIRMWARE_UPDATE_MD_REQUEST_REPORT: {id: 0x04},
	FIRMWARE_UPDATE_MD_GET: {id: 0x05, decode_fmt: {num_of_reports: 1, report_num: 2}},
	FIRMWARE_UPDATE_MD_REPORT: {id: 0x06},
	FIRMWARE_UPDATE_MD_STATUS_REPORT: {id: 0x07},
	FIRMWARE_UPDATE_ACTIVATION_SET: {id: 0x08},
	FIRMWARE_UPDATE_ACTIVATION_STATUS_REPORT: {id: 0x09}
    }
};

zwave_cc_basic.BATTERY = {
    id: 0x80,
    cmd: {
	BATTERY_GET: {id: 0x02, encode_fmt: {}},
	BATTERY_REPORT: {id: 0x03, decode_fmt: [{level: 1, flags: 2}, {level: 1}]}
    }
};

zwave_cc_basic.WAKE_UP = {
    id: 0x84,
    cmd: {
	WAKE_UP_INTERVAL_SET: {id: 0x04, encode_fmt: {secs: 3, nodeid: 1}},
	WAKE_UP_INTERVAL_GET: {id: 0x05, encode_fmt: {}},
	WAKE_UP_INTERVAL_REPORT: {id: 0x06, decode_fmt: {secs: 3, nodeid: 1}},
	WAKE_UP_NOTIFICATION: {id: 0x07, decode_fmt: {}},
	WAKE_UP_NO_MORE_INFORMATION: {id: 0x08, encode_fmt: {}},
	WAKE_UP_INTERVAL_CAPABILITIES_GET: {id: 0x09, fmt: {}},
	WAKE_UP_INTERVAL_CAPABILITIES_REPORT: {id: 0x0A, fmt: {}}
    }
};

zwave_cc_basic.ASSOCIATION = {
    id: 0x85,
    cmd: {
	ASSOCIATION_SET: {id: 0x01, encode_fmt: {group: 1, node_list: 0}},
	ASSOCIATION_GET: {id: 0x02, encode_fmt: {group: 1}},
	ASSOCIATION_REPORT: {id: 0x03, decode_fmt:
			     {group: 1, max_nodes_supported: 1, reports_to_follow: 1, node_list: 0}},
	ASSOCIATION_REMOVE: {id: 0x04, encode_fmt: {group: 1, node_list: 0}},
	ASSOCIATION_GROUPINGS_GET: {id: 0x05, encode_fmt: {}},
	ASSOCIATION_GROUPINGS_REPORT: {id: 0x06, decode_fmt: {supported: 1}},
	ASSOCIATION_SPECIFIC_GROUP_GET: {id: 0x0B, encode_fmt: {}},
	ASSOCIATION_SPECIFIC_GROUP_REPORT: {id: 0x0C, decode_fmt: {group: 1}}
    }
};

zwave_cc_basic.VERSION = {
    id: 0x86,
    cmd: {
	VERSION_GET: {id: 0x11, encode_fmt: {}},
	VERSION_REPORT: {id: 0x12, decode_fmt: {info: 0}},
	VERSION_COMMAND_CLASS_GET: {id: 0x13, encode_fmt: {cc_id:1}},
	VERSION_COMMAND_CLASS_REPORT: {id: 0x14, decode_fmt: {cc_id:1, version: 1}}
    }
};
