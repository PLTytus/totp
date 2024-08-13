function base32tohex(msg) {
	let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
	bits = "",
	hex = "";

	for(let i = 0; i < msg.length; i++){
		let val = base32chars.indexOf(msg.charAt(i).toUpperCase());
		bits += val.toString(2).padStart(5, "0");
	}

	for(let i = 0; i + 4 <= bits.length; i += 4){
		let chunk = bits.substring(i, i + 4);
		hex = hex + parseInt(chunk, 2).toString(16);
	}
	return hex;
}

function hexToArrayBuffer(hex, capacity=0){
	const byteLength = ((hex.length & 1) === 0 ? hex.length : hex.length + 1) >> 1;

	capacity = capacity || 0;
	hex = hex.padStart(byteLength << 1, "0");
	capacity = Math.max(byteLength, capacity);
	const buffer = new ArrayBuffer(capacity);
	const bufferView = new Uint8Array(buffer);

	for(let i = 0; i < byteLength; i++){
		bufferView[i + capacity - byteLength] = parseInt(hex.substring(i << 1, (i << 1) + 2), 16);
	}

	return buffer;
}

document.onreadystatechange = () => {
	if(document.readyState != "complete") return;

	let _fint = () => {
		const subtle = crypto.subtle;
		const ts = Math.round(Date.now() / 1e3);
		const le = 30 - (ts % 30);
		const input = document.querySelector("#secret")
		
		const lecont = document.querySelector("#tleft");
		lecont.setAttribute("data-tleft", String(le).padStart(2, "0"));
		lecont.style.setProperty("--angle", (le / 30 * 360) + "deg");
		
		subtle
			.importKey("raw", hexToArrayBuffer(base32tohex((input.value || input.placeholder).trim())), { name: "HMAC", hash: "SHA-1" }, false, ["sign"])
			.then(key => subtle.sign({ name: "HMAC", hash: "SHA-1" }, key, hexToArrayBuffer(Math.floor(ts / 30).toString(16), 8)))
			.then(hmac => new Uint8Array(hmac))
			.then(hmac => {
				const offset = hmac[hmac.length - 1] & 0xf;
				const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
				return String(code % 1e6).padStart(6, "0");
			})
			.then(totp => document.querySelector("#code").value = totp)
	};

	_fint();

	setInterval(_fint, 1000);

	["input", "change"].forEach(e => document.querySelector("#secret").addEventListener(e, _fint));

	document.querySelector("#code").addEventListener("click", (e) => {
		e.target.focus();
		e.target.select();
	});
};
