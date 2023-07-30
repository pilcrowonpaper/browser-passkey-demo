export function encodeBase64(data: ArrayLike<number> | ArrayBufferLike) {
	return btoa(String.fromCharCode(...new Uint8Array(data)));
}

export function encodeBase64Url(data: ArrayLike<number> | ArrayBufferLike) {
	return encodeBase64(data)
		.replaceAll("=", "")
		.replaceAll("+", "-")
		.replaceAll("/", "_");
}

export function decodeBase64Url(data: string) {
	return decodeBase64(data.replaceAll("-", "+").replaceAll("_", "/"));
}

export function decodeBase64(data: string) {
	return Uint8Array.from(atob(data).split(""), (x) => x.charCodeAt(0));
}

export function utf8Decode(buffer: BufferSource) {
	const textDecoder = new TextDecoder();
	return textDecoder.decode(buffer);
}
