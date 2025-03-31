let publicKey, privateKey;

// Generate RSA Key Pair
function generateKeys() {
    let crypt = new JSEncrypt({ default_key_size: 1024 });
    publicKey = crypt.getPublicKey();
    privateKey = crypt.getPrivateKey();
    document.getElementById("keysOutput").value = "Keys Generated Successfully!";
}

// Encrypt Message
function encryptMessage() {
    let crypt = new JSEncrypt();
    crypt.setPublicKey(publicKey);
    let message = document.getElementById("encryptMessage").value;
    let encrypted = crypt.encrypt(message);
    document.getElementById("encryptOutput").value = encrypted || "Encryption failed!";
}

// Decrypt Message
function decryptMessage() {
    let crypt = new JSEncrypt();
    crypt.setPrivateKey(privateKey);
    let encryptedMessage = document.getElementById("decryptInput").value;
    let decrypted = crypt.decrypt(encryptedMessage);
    document.getElementById("decryptOutput").value = decrypted || "Decryption failed!";
}

// Sign Message
function signMessage() {
    let crypt = new JSEncrypt();
    crypt.setPrivateKey(privateKey);
    let message = document.getElementById("signMessage").value;
    let signature = crypt.sign(message, CryptoJS.SHA256, "sha256");
    document.getElementById("signOutput").value = signature || "Signing failed!";
}

// Verify Signature
function verifySignature() {
    let crypt = new JSEncrypt();
    crypt.setPublicKey(publicKey);
    let message = document.getElementById("verifyMessage").value;
    let signature = document.getElementById("verifySignature").value;
    let isValid = crypt.verify(message, signature, CryptoJS.SHA256);
    document.getElementById("verifyOutput").value = isValid ? "Valid Signature!" : "Invalid Signature!";
}
