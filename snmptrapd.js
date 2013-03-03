var s = require('dgram').createSocket('udp4');
var decoder = require('./dGramDecoder');

s.bind(1621);
s.on("message", function(msg, rinfo) {
	console.log("--------");
	console.log("server got: " + msg.length + " Bytes  from: " + rinfo.address + ":" + rinfo.port);
	console.log(msg.toString('hex'));
	var dGram = new SNMPdGram(msg);
	var pdu = dGram.readPDU();
	console.log("--------");
	console.log(JSON.stringify(dGram.head, null, 4));
	console.log(JSON.stringify(pdu, null, 4));
});


function SNMPdGram(msg) {
	this.dGram = msg;
	this.pduStart = -1; // need to read header to figure out its size
	this.readHeader();
}
SNMPdGram.prototype.readHeader = function() {
	var offset = 2; // skip the 2 first bytes that should be ASN1[0x30]
	var version = decoder.BERReader.INT.read(this.dGram, offset);
	offset += version.size + 2;
	var community = decoder.BERReader.STR.read(this.dGram, offset);
	offset += community.size + 2;
	var pduType = this.dGram[offset];
	var pduLength = this.dGram[++offset];
	var reqID = decoder.BERReader.INT.read(this.dGram, ++offset);
	offset += reqID.size+ 2;
	var errorStatus = decoder.BERReader.INT.read(this.dGram, offset);
	offset += errorStatus.size + 2;
	var errorIndex = decoder.BERReader.INT.read(this.dGram, offset);

	var head = {
		'version': version.value + 1,
		'community': community.value,
		'pduType': pduType,
		'pduLength': pduLength,
		'reqID': reqID.value,
		'errorStatus': errorStatus.value,
		'errorIndex': errorIndex.value,
	};
	this.head = head;
	this.pduStart = offset + errorIndex.size + 2;
	this.uptime = null;

	return head;
};
SNMPdGram.prototype.readPDU = function() {
	if(this.pduStart < 0) this.readHeader();
	this.pdu = decoder.decodeBER(this.dGram, this.pduStart);
	return this.pdu;
}
