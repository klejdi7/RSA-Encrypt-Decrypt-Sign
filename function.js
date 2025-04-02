let publicKeyA, privateKeyA, publicKeyB, privateKeyB;

function generateKeys() {
    let cryptA = new JSEncrypt({ default_key_size: 1024 });
    publicKeyA = cryptA.getPublicKey();
    privateKeyA = cryptA.getPrivateKey();

    let cryptB = new JSEncrypt({ default_key_size: 1024 });
    publicKeyB = cryptB.getPublicKey();
    privateKeyB = cryptB.getPrivateKey();

    document.getElementById("keysOutput").value = "Keys Generated Successfully!";
    console.log("Public Key A:", publicKeyA);
    console.log("Private Key A:", privateKeyA);
    console.log("Public Key B:", publicKeyB);
    console.log("Private Key B:", privateKeyB);
}

// Encrypt message using B's public key
function encryptMessage() {
    if (!publicKeyB) {
        alert("Public Key B is missing! Generate keys first.");
        return;
    }

    let crypt = new JSEncrypt();
    crypt.setPublicKey(publicKeyB);
    let message = document.getElementById("encryptMessage").value;
    let encrypted = crypt.encrypt(message);

    if (!encrypted) {
        document.getElementById("encryptOutput").value = "Encryption failed!";
        return;
    }

    document.getElementById("encryptOutput").value = encrypted;
}

// Decrypt message using B's private key
function decryptMessage() {
    if (!privateKeyB) {
        alert("Private Key B is missing! Generate keys first.");
        return;
    }

    let crypt = new JSEncrypt();
    crypt.setPrivateKey(privateKeyB);
    let encryptedMessage = document.getElementById("decryptInput").value;
    let decrypted = crypt.decrypt(encryptedMessage);

    if (!decrypted) {
        document.getElementById("decryptOutput").value = "Decryption failed!";
        return;
    }

    document.getElementById("decryptOutput").value = decrypted;
}

// Sign message using A's private key
function signMessage() {
    if (!privateKeyA) {
        alert("Private Key A is missing! Generate keys first.");
        return;
    }

    let crypt = new JSEncrypt();
    crypt.setPrivateKey(privateKeyA);
    let message = document.getElementById("signMessage").value;
    let hash = CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);

    console.log("Signing Message Hash:", hash);
    let signed = crypt.sign(hash, CryptoJS.SHA256, "sha256");

    if (!signed) {
        document.getElementById("signOutput").value = "Signing failed!";
        return;
    }

    document.getElementById("signOutput").value = signed;
}

// Verify signature using A's public key
function verifySignature() {
    if (!publicKeyA) {
        alert("Public Key A is missing! Generate keys first.");
        return;
    }

    let crypt = new JSEncrypt();
    crypt.setPublicKey(publicKeyA);
    let message = document.getElementById("verifyMessage").value;
    let signature = document.getElementById("verifySignature").value;
    let hash = CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);

    console.log("Verifying Signature:", signature);
    let isValid = crypt.verify(hash, signature, CryptoJS.SHA256);

    document.getElementById("verifyOutput").value = isValid ? "Valid Signature!" : "Invalid Signature!";
}

// Sign a message and encrypt it
function signAndEncrypt() {
    if (!privateKeyA || !publicKeyB) {
        alert("Keys are missing! Generate keys first.");
        return;
    }

    let cryptSign = new JSEncrypt();
    cryptSign.setPrivateKey(privateKeyA);

    let message = document.getElementById("signedEncryptedMessage").value;
    let hash = CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);
    
    alert("Signing Message Hash: " + hash);

    let signed = cryptSign.sign(hash, CryptoJS.SHA256, "sha256");

    if (!signed) {
        alert("Signing failed!");
        document.getElementById("signedEncryptedOutput").value = "Signing failed!";
        return;
    }

    alert("Signed Message: " + signed.substring(0, 50) + "...");

    if (!publicKeyB) {
        alert("Public Key B is missing!");
        return;
    }

    let cryptEncrypt = new JSEncrypt();
    cryptEncrypt.setPublicKey(publicKeyB);

    // **Fix: Hash the signed message before encrypting**
    let signedHash = CryptoJS.SHA256(signed).toString(CryptoJS.enc.Hex);

    alert("Hash of Signed Message: " + signedHash);

    let encrypted = cryptEncrypt.encrypt(signedHash);

    if (!encrypted) {
        alert("Encryption failed! Even after hashing, message might be too long.");
        document.getElementById("signedEncryptedOutput").value = "Encryption failed!";
        return;
    }

    alert("Encryption Successful!");
    document.getElementById("signedEncryptedOutput").value = encrypted;
}

// Decrypt a signed message and verify it
function decryptAndVerify() {
    if (!privateKeyB || !publicKeyA) {
        alert("Keys are missing! Generate keys first.");
        return;
    }

    let cryptDecrypt = new JSEncrypt();
    cryptDecrypt.setPrivateKey(privateKeyB);
    let encrypted = document.getElementById("decryptAndVerifyInput").value;
    let decrypted = cryptDecrypt.decrypt(encrypted);

    if (!decrypted) {
        document.getElementById("decryptAndVerifyOutput").value = "Decryption failed!";
        return;
    }

    console.log("Decrypted Signed Message:", decrypted);

    let cryptVerify = new JSEncrypt();
    cryptVerify.setPublicKey(publicKeyA);
    let hash = CryptoJS.SHA256(decrypted).toString(CryptoJS.enc.Hex);
    let isValid = cryptVerify.verify(hash, decrypted, CryptoJS.SHA256);

    console.log("Signature Valid:", isValid);
    document.getElementById("decryptAndVerifyOutput").value = isValid ? "Signature Verified!" : "Signature Invalid!";
}