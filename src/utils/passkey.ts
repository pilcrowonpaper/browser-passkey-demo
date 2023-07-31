import { encodeBase64Url, utf8Decode } from "./encode";

// based on https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion
export async function verifyAssertion(
	credential: PublicKeyCredential,
	options: {
		publicKey: ArrayBuffer;
		challenge: ArrayBuffer;
	},
): Promise<void> {
	// see verifyAssertion() (above) for additional comments
	const response = credential.response;
	if (!(response instanceof AuthenticatorAssertionResponse)) {
		throw new TypeError();
	}
	const clientData = JSON.parse(utf8Decode(response.clientDataJSON)) as {
		type: string;
		challenge: string; // base64url encoded challenge
		origin: string; // url origin
	};
	if (clientData.type !== "webauthn.get") {
		throw new Error("Failed to verify 'clientData.type'");
	}
	if (clientData.challenge !== encodeBase64Url(options.challenge)) {
		throw new Error("Failed to verify 'clientData.challenge'");
	}
	if (clientData.origin !== window.location.origin) {
		throw new Error("Failed to verify 'clientData.origin");
	}

	const authData = new Uint8Array(response.authenticatorData);
	if (authData.byteLength < 37) {
		throw new Error("Malformed 'authData'");
	}
	const rpIdHash = authData.slice(0, 32);
	const rpIdData = new TextEncoder().encode(window.location.hostname);
	const expectedRpIdHash = await crypto.subtle.digest("SHA-256", rpIdData);
	// compare buffer
	if (!bytesEquals(rpIdHash, expectedRpIdHash)) {
		throw new Error("Failed to verify 'rpId' hash");
	}
	const flagsBits = authData[32].toString(2);
	if (flagsBits.charAt(flagsBits.length - 1) !== "1") {
		throw new Error("Failed to verify user present flag");
	}

	// the signature is encoded in DER
	// so we need to convert into ECDSA compatible format
	const signature = convertDERSignatureToECDSASignature(response.signature);
	const hash = await crypto.subtle.digest("SHA-256", response.clientDataJSON);
	const data = concatenateBuffer(authData, hash);
	const verifiedSignature = await crypto.subtle.verify(
		{
			name: "ECDSA",
			hash: "SHA-256",
		},
		await crypto.subtle.importKey(
			"spki",
			options.publicKey,
			{
				name: "ECDSA",
				namedCurve: "P-256",
			},
			true,
			["verify"],
		),
		signature,
		data,
	);
	if (!verifiedSignature) {
		throw new Error("Failed to verify signature");
	}

	// we can ignore signCount when using passkeys
}

// DER signature consists of several parts:
// 1 byte: `48` (header byte)
// 1 byte: total byte length - header byte length (1)
// 1 byte: `2` (header byte indicating an integer)
// 1 byte: r value byte length
// around 32 bytes: r value
// 1 byte: `2` (header byte indicating an integer)
// 1 byte: s value byte length
// around 32 bytes: s value
// (end - total of around 70 bytes)

// ECDSA signature is the sequence of:
// r value (32 bytes)
// s value (32 bytes)
function convertDERSignatureToECDSASignature(
	DERSignature: ArrayLike<number> | ArrayBufferLike,
): ArrayBuffer {
	const signatureBytes = new Uint8Array(DERSignature);

	const rStart = 4;
	const rLength = signatureBytes[3];
	const rEnd = rStart + rLength;
	const DEREncodedR = signatureBytes.slice(rStart, rEnd);
	// DER encoded 32 bytes integers can have leading 0x00s or be smaller than 32 bytes
	const r = decodeDERInteger(DEREncodedR, 32);

	const sStart = rEnd + 2;
	const sEnd = signatureBytes.byteLength;
	const DEREncodedS = signatureBytes.slice(sStart, sEnd);
	// repeat the process
	const s = decodeDERInteger(DEREncodedS, 32);

	const ECDSASignature = new Uint8Array([...r, ...s]);
	return ECDSASignature.buffer;
}

function decodeDERInteger(
	integerBytes: Uint8Array,
	expectedLength: number,
): Uint8Array {
	if (integerBytes.byteLength === expectedLength) return integerBytes;
	if (integerBytes.byteLength < expectedLength) {
		return concatenateUint8Array(
			// add leading 0x00s if smaller than expected length
			new Uint8Array(expectedLength - integerBytes.byteLength).fill(0),
			integerBytes,
		);
	}
	// remove leading 0x00s if larger then expected length
	return integerBytes.slice(-32);
}

function bytesEquals(
	buffer1: ArrayBuffer | Uint8Array,
	buffer2: ArrayBuffer | Uint8Array,
) {
	const bytes1 = new Uint8Array(buffer1);
	const bytes2 = new Uint8Array(buffer2);
	if (bytes1.byteLength !== bytes2.byteLength) return false;
	for (let i = 0; i < bytes1.byteLength; i++) {
		if (bytes1[i] !== bytes2[i]) return false;
	}
	return true;
}

function concatenateBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer) {
	return concatenateUint8Array(new Uint8Array(buffer1), new Uint8Array(buffer2))
		.buffer;
}

function concatenateUint8Array(bytes1: Uint8Array, bytes2: Uint8Array) {
	const result = new Uint8Array(bytes1.byteLength + bytes2.byteLength);
	result.set(new Uint8Array(bytes1), 0);
	result.set(new Uint8Array(bytes2), bytes1.byteLength);
	return result;
}
