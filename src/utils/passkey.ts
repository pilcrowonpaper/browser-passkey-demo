import { encodeBase64Url, utf8Decode } from "./encode";

export async function verifyAttestation(
	credential: PublicKeyCredential,
	options: {
		challenge: ArrayBuffer;
		origin: string;
	},
): Promise<ArrayBuffer> {
	const response = credential.response;
	if (!(response instanceof AuthenticatorAttestationResponse)) {
		throw new Error("Failed to verify attestation");
	}
	const clientData = JSON.parse(utf8Decode(response.clientDataJSON)) as unknown;
	if (typeof clientData !== "object" || clientData === null) {
		throw new Error("Failed to verify attestation");
	}
	if (!("type" in clientData) || clientData.type !== "webauthn.create") {
		throw new Error("Failed to verify attestation");
	}
	if (
		!("challenge" in clientData) ||
		clientData.challenge !== encodeBase64Url(options.challenge)
	) {
		throw new Error("Failed to verify attestation");
	}
	if (!("origin" in clientData) || clientData.origin !== options.origin) {
		throw new Error("Failed to verify attestation");
	}

	const authData = new Uint8Array(response.getAuthenticatorData());
	const rpIdHash = authData.slice(0, 32);
	const rpIdData = new TextEncoder().encode("localhost");
	const expectedRpIdHash = await crypto.subtle.digest("SHA-256", rpIdData);
	if (!bytesEquals(rpIdHash, expectedRpIdHash)) {
		throw new Error("Failed to verify attestation");
	}
	if (authData.byteLength < 37) throw new Error();
	const flagsByte = authData.at(32) ?? null;
	if (flagsByte === null) {
		throw new Error("Failed to verify attestation");
	}
	const flagsBits = flagsByte.toString(2);
	// check if user present flag (least significant bit) is 1
	if (flagsBits.charAt(flagsBits.length - 1) !== "1") {
		throw new Error("Failed to verify attestation");
	}
	const COSEAlgorithmId = response.getPublicKeyAlgorithm();
	if (COSEAlgorithmId !== -7) {
		throw new Error("Failed to verify attestation");
	}
	// we can ignore signCount when using passkeys

	const publicKey = response.getPublicKey();
	if (!publicKey) {
		throw new Error("Failed to verify attestation");
	}
	return publicKey;
}

export async function verifyAssertion(
	credential: PublicKeyCredential,
	options: {
		publicKey: ArrayBuffer;
		challenge: ArrayBuffer;
		origin: string;
	},
): Promise<void> {
	const response = credential.response;
	if (!(response instanceof AuthenticatorAssertionResponse)) {
		throw new Error("Failed to verify assertion");
	}
	// cData = clientDataJSON
	const cData = response.clientDataJSON;
	// authData = response.authenticatorData
	const authData = new Uint8Array(response.authenticatorData);
	const sig = response.signature;
	const JSONtext = utf8Decode(cData);
	const C = JSON.parse(JSONtext) as {
		type: string;
		challenge: string;
		origin: string;
		// tokenBinding.status  ????? missing???
	};
	if (C.type !== "webauthn.get") {
		throw new Error("Failed to verify assertion");
	}
	if (C.challenge !== encodeBase64Url(options.challenge)) {
		throw new Error("Failed to verify assertion");
	}
	if (C.origin !== options.origin) {
		throw new Error("Failed to verify assertion");
	}
	const rpIdHash = authData.slice(0, 32);
	const rpIdData = new TextEncoder().encode("localhost");
	const expectedRpIdHash = await crypto.subtle.digest("SHA-256", rpIdData);
	if (!bytesEquals(rpIdHash, expectedRpIdHash)) {
		throw new Error("Failed to verify assertion");
	}
	const flagsByte = new Uint8Array(authData).at(32) ?? null;
	if (flagsByte === null) {
		throw new Error("Failed to verify assertion");
	}
	const flagsBits = flagsByte.toString(2);
	// check if user present flag (least significant bit) is 1
	if (flagsBits.charAt(flagsBits.length - 1) !== "1") {
		throw new Error("Failed to verify assertion");
	}

	const hash = await crypto.subtle.digest("SHA-256", cData);
	const verifiedSignature = await crypto.subtle.verify(
		{
			name: "ECDSA",
			hash: "SHA-256",
		},
		await crypto.subtle.importKey(
			"spki",
			options.publicKey, // ArrayBuffer from publicKeyCredential.response.getPublicKey()
			{
				name: "ECDSA",
				namedCurve: "P-256",
			},
			true,
			["verify"],
		),
		// the signature is encoded in DER
		// so we need to convert into ECDSA compatible format
		convertDERSignatureToECDSASignature(sig),
		concatenateBuffer(authData, hash),
	);
	if (!verifiedSignature) {
		throw new Error("Failed to verify assertion");
	}

	// we can ignore signCount when using passkeys
}

// DER signature consists of several parts:
// 1 byte: 48 (header byte)
// 1 byte: total byte length - 1
// 1 byte: 2 (header byte indicating an integer)
// 1 byte: r value byte length
// around 32 bytes: r value
// 1 byte: 2 (header byte indicating an integer)
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

// remove leading 0x00s if larger then expected length
// or add leading 0x00s if smaller than expected length
function decodeDERInteger(
	integerBytes: Uint8Array,
	expectedLength: number,
): Uint8Array {
	if (integerBytes.byteLength === expectedLength) return integerBytes;
	if (integerBytes.byteLength < expectedLength) {
		return concatenateUint8Array(
			new Uint8Array(expectedLength - integerBytes.byteLength).fill(0),
			integerBytes,
		);
	}
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
