// Replace the credential creation call
navigator.credentials.create = (options) => {
	// Recursively encodes objects into JSON safe primitives (ex: base64)
	let encode = (obj) => {
		if (Array.isArray(obj)) {
			return obj.map((elem) => encode(elem));
		} else if (obj instanceof ArrayBuffer) {
			return btoa(String.fromCharCode(...new Uint8Array(obj)));;
		} else if (Object(obj) === obj) {
			return Object.fromEntries(Object.entries(obj).map(([key, value]) => [key, encode(value)]));
		} else {
			return obj;
		}
	}
	// Make an "API" request to sign given the parameters
	return fetch("https://webauthn.bored.engineer/make_credential", {
		"method": "POST",
		"mode": "cors",
		"body": JSON.stringify(encode(options.publicKey)),
		"headers": {
			"Content-Type": "application/json",
		}
	}).then((resp) => {
		// Reject with the response body if not a 200 status
		return resp.ok ? resp.json() : resp.text().then(Promise.reject.bind(Promise));
	}).then((body) => {
		// Convert the response into a psuedo-PublicKeyCredential object
		return Promise.resolve({
			"id": body.id,
			"rawId": Uint8Array.from(atob(body.id), c => c.charCodeAt(0)),
			"type": "public-key",
			"response": {
				"clientDataJSON": (new TextEncoder()).encode(body.client_data).buffer,
				"attestationObject": Uint8Array.from(atob(body.attestation_object), c => c.charCodeAt(0)).buffer,
			}
		});
	}).catch((error) => {
		// Alert errors visibily and also return them
		alert(`Failure:\n${error}`);
		return Project.reject(error);
	});
}
