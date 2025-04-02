let publicKeyA, privateKeyA, publicKeyB, privateKeyB;

function generateKeys() {
    let cryptA = new JSEncrypt({ default_key_size: 1024 });
    publicKeyA = cryptA.getPublicKey();
    privateKeyA = cryptA.getPrivateKey();

    let cryptB = new JSEncrypt({ default_key_size: 1024 });
    publicKeyB = cryptB.getPublicKey();
    privateKeyB = cryptB.getPrivateKey();

    document.getElementById("keysOutput").value = "Keys Generated Successfully!";
}

// Encryption
function encryptMessage() {
    let crypt = new JSEncrypt();
    crypt.setPublicKey(publicKeyB);
    let message = document.getElementById("encryptMessage").value;
    document.getElementById("encryptOutput").value = crypt.encrypt(message) || "Encryption failed!";
}

// Decryption
function decryptMessage() {
    let crypt = new JSEncrypt();
    crypt.setPrivateKey(privateKeyB);
    let encryptedMessage = document.getElementById("decryptInput").value;
    document.getElementById("decryptOutput").value = crypt.decrypt(encryptedMessage) || "Decryption failed!";
}

// Signing
function signMessage() {
    let crypt = new JSEncrypt();
    crypt.setPrivateKey(privateKeyA);
    let message = document.getElementById("signMessage").value;
    let hash = CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
    document.getElementById("signOutput").value = crypt.sign(hash, CryptoJS.SHA256, "sha256") || "Signing failed!";
}

// Verification
function verifySignature() {
    let crypt = new JSEncrypt();
    crypt.setPublicKey(publicKeyA);
    let message = document.getElementById("verifyMessage").value;
    let signature = document.getElementById("verifySignature").value;
    let hash = CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
    document.getElementById("verifyOutput").value = crypt.verify(hash, signature, CryptoJS.SHA256) ? "Valid Signature!" : "Invalid Signature!";
}

// Signed & Encrypted Message
function signAndEncrypt() {
    let cryptSign = new JSEncrypt();
    cryptSign.setPrivateKey(privateKeyA);
    let message = document.getElementById("signedEncryptedMessage").value;
    let hash = CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
    let signed = cryptSign.sign(hash, CryptoJS.SHA256, "sha256");

    let cryptEncrypt = new JSEncrypt();
    cryptEncrypt.setPublicKey(publicKeyB);
    document.getElementById("signedEncryptedOutput").value = cryptEncrypt.encrypt(signed) || "Signing & Encryption failed!";
}

// Decrypt & Verify
function decryptAndVerify() {
    let cryptDecrypt = new JSEncrypt();
    cryptDecrypt.setPrivateKey(privateKeyB);
    let encrypted = document.getElementById("decryptAndVerifyInput").value;
    let decrypted = cryptDecrypt.decrypt(encrypted);

    let cryptVerify = new JSEncrypt();
    cryptVerify.setPublicKey(publicKeyA);
    let hash = CryptoJS.SHA256(decrypted).toString(CryptoJS.enc.Hex);
    let isValid = cryptVerify.verify(hash, decrypted, CryptoJS.SHA256);

    document.getElementById("decryptAndVerifyOutput").value = isValid ? "Signature Verified!" : "Signature Invalid!";
}