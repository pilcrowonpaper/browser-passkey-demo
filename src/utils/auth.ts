import { db } from "./db";
import { decodeBase64Url, encodeBase64Url } from "./encode";
import { verifyAttestation, verifyAssertion } from "./passkey";

type User = {
	userId: string;
	username: string;
};

export async function signUp(username: string): Promise<User> {
	// should be handled in server - start
	const userExists = !!db.getByUsername(username);
	if (userExists) throw new Error("Username already used");
	// recommend minimum 16 bytes
	const challenge = crypto.getRandomValues(new Uint8Array(32));
	// should be handled in server - end

	const publicKeyCredential = await navigator.credentials.create({
		// publicKey = Web Authentication API
		publicKey: {
			rp: { name: "Passkey Demo" },
			user: {
				name: username,
				id: crypto.getRandomValues(new Uint8Array(32)),
				displayName: username,
			},
			pubKeyCredParams: [
				{
					type: "public-key",
					// use ECDSA with the secp256k1 curve and the SHA-256 (aka. ES256K)
					// based on IANA COSE Algorithms registry id
					alg: -7,
				},
			],
			challenge,
			authenticatorSelection: { authenticatorAttachment: "platform" },
		},
	});
	if (!(publicKeyCredential instanceof PublicKeyCredential)) {
		throw new Error("Failed to validate");
	}

	// should be handled in server - start
	const userId = generateId(8);
	const publicKey = await verifyAttestation(publicKeyCredential, {
		challenge,
	});
	db.insert({
		id: userId,
		credential_id: publicKeyCredential.id, // base64url encoded
		username,
		public_key: encodeBase64Url(publicKey),
	});
	// should be handled in server - end

	return { userId, username };
}

export async function signIn(): Promise<User> {
	// should be generated in server
	// recommend minimum 16 bytes
	const challenge = crypto.getRandomValues(new Uint8Array(32));

	const publicKeyCredential = await navigator.credentials.get({
		publicKey: {
			challenge,
		},
	});
	if (!(publicKeyCredential instanceof PublicKeyCredential)) {
		throw new Error("Failed to verify assertion");
	}

	// should be handled in server - start
	const databaseUser = db.getByCredentialId(publicKeyCredential.id);
	if (!databaseUser) {
		throw new Error("User does not exist");
	}

	await verifyAssertion(publicKeyCredential, {
		publicKey: decodeBase64Url(databaseUser.public_key),
		challenge,
	});
	// should be handled in server - end

	return {
		userId: databaseUser.id,
		username: databaseUser.username,
	};
}

// the most inefficient random id generator
// possible characters: 0-9, a-z
export function generateId(length: number) {
	let result = "";
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
	while (result.length !== length) {
		const index = Math.floor(crypto.getRandomValues(new Uint8Array(1))[0] / 4);
		if (index >= alphabet.length) continue;
		result += alphabet[index];
	}
	return result;
}
