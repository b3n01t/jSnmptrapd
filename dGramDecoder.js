/*
* This is the bit playground!
*
* References:
* 		http://www.vijaymukhi.com/vmis/bersnmp.htm
* 		http://lapo.it/asn1js/
* And:
* 		/usr/share/snmp/mibs/SNMPv2-SMI.txt for application type definitions
*/

function decodeBER(buffer, offset) {
	var of = offset || 0;
	var depth = depth || 0;
	var current = of;
	var type = buffer[of];
	var len = buffer[of+1];
	
	if(ASN1SnmpTags[type] === undefined) {
		throw '@' + (of) + ' 0x' + (type).toString(16) + ' Tag Not Regconised';
	}
	if(ASN1SnmpTags[type].primitive === true) {
		var val = ASN1SnmpTags[type].reader.read(buffer, current);
		val.type = ASN1SnmpTags[type].typeName;
		return val;
	} else {
		var seq = [];
		seq.size = len;
		var next = of + 2;
		while(next < of + 2 + len){
			var sub = decodeBER(buffer,next);	
			next = next + sub.size + 2;
			seq.push(sub);
		}
		return seq;
	}
}

var BERReader = {
	INT: {
		tags: [0x02, 0x45],
		read: function(buf, offset) {
			var of = offset || 0;
			if(this.tags.indexOf(buf[of]) < 0) throw 'TagError: 0x' + (buf[of]).toString(16) + '@' + of + ' not in ' + this.tags;
			var size = buf[++of];
			var fb = buf[++of];
			var value = 0;
			value = fb & 0x7F;
			for(var i = 1; i < size; i++) {
				value <<= 8;
				value |= (buf[++of] & 0xff);
			}
			if((fb & 0x80) == 0x80) value = -value;

			return {
				value: value,
				'size': size
			}
		}
	},
	UINT64: {
		tags: [0x46, 0x47],
		read: function(buf, offset) {
			var of = offset || 0;
			if(this.tags.indexOf(buf[of]) < 0) throw 'TagError: 0x' + (buf[of]).toString(16) + '@' + of + ' not in ' + this.tags;
			var size = buf[++of];
			var value = buf.readUInt64BE(++of); //coded on 9 octect ??...
			return {
				value: value,
				'size': size
			}
		}
	},
	UINT: {
		tags: [0x41, 0x42, 0x43],
		read: function(buf, offset) {
			var of = offset || 0;
			if(this.tags.indexOf(buf[of]) < 0) throw 'TagError: 0x' + (buf[of]).toString(16) + '@' + of + ' not in ' + this.tags;
			var size = buf[++of];
			var value = 0;
			if(size > 4) {
				value = buf.readUInt32BE(++of + (size - 4)); //coded on 5 octect...	
			} else if(size < 4) {
				var tmp = new Buffer(4);
				tmp.fill(0x0);
				for(var i = 0; i < size; i++) {
					tmp[(4 - size) + i] = buf[++of];
				}
				value = tmp.readUInt32BE(0);
			} else {
				value = buf.readUInt32BE(++of);
			}
			return {
				value: value,
				'size': size
			}
		}
	},
	STR: {
		tags: [0x04, 0x44],
		read: function(buf, offset) {
			var of = offset || 0;
			if(this.tags.indexOf(buf[of]) < 0) throw 'TagError: ' + buf[of] + '@' + of + ' not in ' + this.tags;
			var size = buf[++of];
			var str = '';
			for(var i = 0; i < size; i++) {
				str += String.fromCharCode(buf[++of]);
			}
			return {
				value: str.toString('utf8'),
				'size': size
			}
		}
	},
	OID: {
		tags: [0x06],
		read: function(buf, offset) {
			var of = offset || 0;
			if(this.tags.indexOf(buf[of]) < 0) throw 'TagError: 0x' + (buf[of]).toString(16) + '@' + of + ' not in ' + this.tags;
			var size = buf[++of];
			var values = [];
			for(var i = 0; i < size; i++) {
				values.push(parseInt(buf[++of]));
			};
			if(values[0] < 40) {
				values.unshift(0);
			} else if(values[0] < 80) {
				values[0] -= 40;
				values.unshift(1);
			} else {
				values[0] -= 80;
				values.unshift(2);
			}

			return {
				value: '.' + values.join('.'),
				'size': size
			};
		}
	},
	IP: {
		tags: [0x40],
		read: function(buf, offset) {
			var of = offset || 0;
			var len = parseInt(buf[of + 1]);
			var ip = [parseInt(buf[of + 2]), parseInt(buf[of + 3]), parseInt(buf[of + 4]), parseInt(buf[of + 5])];
			return {
				value: ip.join('.'),
				'size': 4
			}

		}
	}
};

var ASN1SnmpTags = { 
// Only ASN1 standard tags used in SNMP and SNMP's app specifics tags
// 0xa7 is a constucted, context-specific type: SNMP trap

	0x02: { // signed (msb is sign)
		'typeName': 'INTEGER',
		'primitive': true,
		'reader': BERReader.INT
	},
	0x04: {
		'typeName': 'OCTET STRING',
		'primitive': true,
		'reader': BERReader.STR
	},
	0x06: {
		'typeName': 'OID',
		'primitive': true,
		'reader': BERReader.OID
	},
	0x30: {
		'typeName': 'SEQUENCE',
		'primitive': false
	},
	0x40: {
		'typeName': 'IP ADDRESS',
		'primitive': true,
		'reader': BERReader.IP
	},
	0x41: {
		'typeName': 'COUNTER',
		'primitive': true,
		'reader': BERReader.UINT
	},
	0x42: {
		'typeName': 'GAUGE',
		'primitive': true,
		'reader': BERReader.UINT
	},
	0x43: {
		'typeName': 'TIME TICKS',
		'primitive': true,
		'reader': BERReader.UINT
	},
	0x44: {
		'typeName': 'OPAQUE',
		'primitive': true,
		'reader': BERReader.STR
	},
	0x45: { // not in snmpv2-smi definition
		'typeName': 'NSAP ADDR',
		'primitive': true,
		'reader': BERReader.INT
	},
	0x46: {
		'typeName': 'COUNTER64',
		'primitive': true,
		'reader': BERReader.UINT64
	},
	0x47: {
		'typeName': 'UINTERGER32',
		'primitive': true,
		'reader': BERReader.UINT64
	}
};

exports.decodeBER = decodeBER;
exports.BERReader = BERReader;
exports.ASN1SnmpTags = ASN1SnmpTags;