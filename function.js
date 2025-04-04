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
    let originalHash = CryptoJS.SHA256(message).toString(CryptoJS.enc.Hex);

    let signed = cryptSign.sign(originalHash, CryptoJS.SHA256, "sha256");

    if (!signed) {
        alert("Signing failed!");
        document.getElementById("signedEncryptedOutput").value = "Signing failed!";
        return;
    }


    let cryptEncrypt = new JSEncrypt();
    cryptEncrypt.setPublicKey(publicKeyB);

    // **Fix: Encrypt the original hash, not the signature**
    let encrypted = cryptEncrypt.encrypt(originalHash);

    if (!encrypted) {
        alert("Encryption failed!");
        document.getElementById("signedEncryptedOutput").value = "Encryption failed!";
        return;
    }

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
    if (!encrypted) {
        alert("Please enter an encrypted message!");
        return;
    }

    let decryptedHash = cryptDecrypt.decrypt(encrypted);

    if (!decryptedHash) {
        alert("Decryption failed!");
        document.getElementById("decryptAndVerifyOutput").value = "Decryption failed!";
        return;
    }


    let originalMessage = document.getElementById("originalMessageForVerification").value;
    if (!originalMessage) {
        alert("Please enter the original message!");
        return;
    }

    let originalHash = CryptoJS.SHA256(originalMessage).toString(CryptoJS.enc.Hex);

    if (originalHash === decryptedHash) {
        document.getElementById("decryptAndVerifyOutput").value = "Signature Verified!";
    } else {
        document.getElementById("decryptAndVerifyOutput").value = "Invalid Signature!";
    }
}
