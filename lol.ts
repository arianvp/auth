interface AuthenticatorResponse {
    toFormData(): FormData
}

AuthenticatorResponse.prototype.toFormData = function (this: AuthenticatorResponse): FormData {
    const formData = new FormData()
    formData.set("clientDataJSON", new Blob([this.clientDataJSON]))
    return formData
}

interface AuthenticatorAttestationResponse {
    toFormData(): FormData
}

AuthenticatorAttestationResponse.prototype.toFormData = function (this: AuthenticatorAttestationResponse): FormData {
    const formData = AuthenticatorResponse.prototype.toFormData.call(this) as FormData
    formData.set("attestationObject", new Blob([this.attestationObject]))
    for (const transport of this.getTransports()) {
        formData.append("transports[]", transport)
    }
    const publicKey = this.getPublicKey()
    if (publicKey) {
        formData.set("publicKey", new Blob([publicKey]))
    }
    formData.set("publicKeyAlgorithm", this.getPublicKeyAlgorithm().toString())
    formData.set("authenticatorData", new Blob([this.getAuthenticatorData()]))
    return formData
}

interface AuthenticatorAssertionResponse {
    toFormData(): FormData
}

AuthenticatorAssertionResponse.prototype.toFormData = function (this: AuthenticatorAssertionResponse): FormData {
    const formData = AuthenticatorResponse.prototype.toFormData.call(this) as FormData
    formData.set("authenticatorData", new Blob([this.authenticatorData]))
    formData.set("signature", new Blob([this.signature]))
    if (this.userHandle) {
        {
            formData.set("userHandle", new Blob([this.userHandle]))
        }
    }
    return formData
}

interface PublicKeyCredential {
    toFormData(): FormData
}

PublicKeyCredential.prototype.toFormData = function (this: PublicKeyCredential) {
    const formData = this.response.toFormData()
    formData.set("type", this.type)
    formData.set("rawId", new Blob([this.rawId]))
    formData.set("id", this.id)
    if (this.authenticatorAttachment) {
        formData.set("authenticatorAttachment", this.authenticatorAttachment)
    }
    return formData
}

async function verifyAttestationResponse(response: AuthenticatorAssertionResponse, key: CryptoKey, challenge : ArrayBuffer) {

    response.authenticatorData
    response.clientDataJSON

    const combined = new Uint8Array(response.authenticatorData.byteLength + response.clientDataJSON.byteLength)
    combined.set(new Uint8Array(response.authenticatorData), 0)
    combined.set(new Uint8Array(response.clientDataJSON), response.authenticatorData.byteLength)
    const clientData = JSON.parse(new TextDecoder('utf-8').decode(response.clientDataJSON))

    const result = await crypto.subtle.verify(
        {
            name: "ECDSA",
            hash: {name: "SHA-256"},
        },
        key,
        response.signature,
        combined
    )
    if (!result) {
        throw new Error("Signature verification failed")
    }

    // WHY IS THE CHALLENGE BASE64 ENCODED IN THE CLIENT DATA JSON?
    // WHY IS THE CHALLENGE BASE64 ENCODED IN THE CLIENT DATA JSON?
    // WHY IS THE CHALLENGE BASE64 ENCODED IN THE CLIENT DATA JSON?


    if (clientData.challenge !== challenge) {
        throw new Error("Challenge mismatch")
    }

    response.signature

}