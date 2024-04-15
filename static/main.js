// elements
const unlockForm = document.getElementById("unlock-form"),
      usernameField = document.getElementById("username"),
      passwordField = document.getElementById("password"),
      unlockError = document.getElementById("unlock-error"),
      saveError = document.getElementById("save-error"),
      createNewCheckbox = document.getElementById("create-new"),
      savingMessage = document.getElementById("saving"),
      vaultView = document.getElementById("vault-view");

const base64ToArrayBuf = base64 => Uint8Array.from(atob(base64), char => char.charCodeAt(0)).buffer;
const arrayBufToBase64 = buf => btoa(Array.prototype.map.call(new Uint8Array(buf), byte => String.fromCharCode(byte)).join(""));

const textEncoder = new TextEncoder(),
      textDecoder = new TextDecoder();

let username = null, masterKey = null, keyHash = null;
let vault = null, counter = null;

const IV_LENGTH = 12;

const decryptVault = async vault => {
    const bytes = new Uint8Array(base64ToArrayBuf(vault));
    const iv = bytes.slice(0, IV_LENGTH), ciphertext = bytes.slice(IV_LENGTH);
    const plaintext = await window.crypto.subtle.decrypt({name: "AES-GCM", iv}, masterKey, ciphertext);
    return {iv, content: JSON.parse(textDecoder.decode(plaintext))};
};

const saveVault = encrypted => {
    window.localStorage.setItem("counter"+keyHash, counter);
    window.localStorage.setItem("vault"+keyHash, encrypted);
};

const encryptLocalVault = async () => {

    // increment IV
    let idx = 0;
    while(1) {
        vault.iv[idx]++;
        if(vault.iv[idx] != 0) {
            break;
        }
        idx++;
    }

    // encrypt
    const plaintext = textEncoder.encode(JSON.stringify(vault.content));
    const ciphertext = new Uint8Array(await window.crypto.subtle.encrypt({name: "AES-GCM", iv: vault.iv}, masterKey, plaintext));
    const vaultEncrypted = new Uint8Array(ciphertext.length + IV_LENGTH);
    vaultEncrypted.set(vault.iv, 0);
    vaultEncrypted.set(ciphertext, IV_LENGTH);
    return arrayBufToBase64(vaultEncrypted);

};

// merge() brings changes from a modified older vault to a newer vault
const merge = async (newerVault, newerCounter) => {
    // TODO
};

// the goal of commitChanges() is to bring the remote view of the vault into sync with the local view
const encryptAndCommit = async () => {

    const vaultStr = await encryptLocalVault();
    window.localStorage.setItem("vault"+keyHash, vaultStr);
    window.localStorage.setItem("dirty"+keyHash, "dirty");

    // try to upload the vault
    const req = fetch("/vault", {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({
            username,
            keyHash,
            counter,
            vault: vaultStr
        })
    });

    if(!req.ok) {
        const resp = await req.json();
        if(resp.conflict) {
            // if the vault changed since we made our changes, fetch the new vault and merge those changes into it
            // then, try to upload the changes again
            merge(await decryptVault(resp.latestVault), resp.counter);
            await encryptAndCommit();
        } else {
            throw new Error("Request failed for unknown reasons");
        }
    } else {
        // if the upload succeeded, then we should increase the counter to match the remote
        counter++;
        window.localStorage.setItem("counter"+keyHash, counter);
        window.localStorage.removeItem("dirty"+keyHash);
    }

};

const commit = async () => {
    savingMessage.style.display = "initial";
    saveError.textContent = "";
    try {
        await encryptAndCommit();
    } catch(error) {
        savingMessage.style.display = "";
        saveError.textContent = "Vault could not be uploaded to remote server";
    }
};

const showVaultView = () => {
    unlockForm.style.display = "none";
    vaultView.style.display = "";
};

const loadLocalVault = async () => {
    vault = await decryptVault(window.localStorage.getItem("vault"+keyHash));
    counter = Number(window.localStorage.getItem("counter"+keyHash));
};

const initializeVault = async () => {

    unlockError.textContent = "";

    // if we want to create a new vault, initialize an empty vault and try to commit it
    if(createNewCheckbox.checked) {
        vault = {
            iv: new Uint8Array(IV_LENGTH),
            content: {}
        };
        counter = 1;
        const encrypted = await encryptLocalVault();
        try {
            const req = await fetch("/vault/create", {
                method: "POST",
                headers: {"content-type": "application/json"},
                body: JSON.stringify({
                    username,
                    keyHash,
                    vault: encrypted
                })
            });
            if(!req.ok) {
                throw new Error("Request failed");
            }
        } catch(error) {
            unlockError.textContent = "Failed to upload vault; it may exist already.";
            return;
        }
        saveVault(encrypted);
        showVaultView();
        return;
    } else if(window.localStorage.getItem("dirty"+keyHash) !== null) {
        
        // if there are uncommitted changes, we need to load the local vault and reconcile with remote
        try {
            await loadLocalVault();
        } catch(error) {
            unlockError.textContent = "Username or password is incorrect, or local vault is corrupted.";
            return;
        }

        await commit();

    } else {

        // do a dummy sync operation; if the counter has increased since the vault was last accessed locally, then we will receive a copy of the vault
        lastCounter = Number(window.localStorage.getItem("counter"+keyHash)) || -1;
        try {

            const req = await fetch("/vault/sync", {
                method: "POST",
                headers: {"content-type": "application/json"},
                body: JSON.stringify({username, keyHash, lastCounter})
            });

            if(!req.ok) {
                const resp = await req.json();
                if(resp.conflict) {
                    vault = await decryptVault(resp.latestVault);
                    counter = resp.counter;
                    saveVault(resp.latestVault);
                    showVaultView();
                } else if(req.status == 404) {
                    unlockError.textContent = "Username or password is incorrect.";
                } else {
                    throw new Error("Request failed for unknown reasons");
                }
            }

        } catch(error) {

            console.error(error);

            // if that failed, load the local and warn the user
            try {
                await loadLocalVault();
                showVaultView();
                saveError.textContent = "Remote server could not be reached, so the last saved copy of the vault was loaded.";
            } catch(error) {
                unlockError.textContent = "Vault unlock failed.";
            }

        }

    }


};

unlockForm.addEventListener("submit", async event => {
    
    // keep page from reloading
    event.preventDefault();

    username = usernameField.value;

    // derive master key from password
    const masterKeyBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: textEncoder.encode("bithole-passwords" + usernameField.value),
            iterations: 1_000_000
        },
        await window.crypto.subtle.importKey(
            "raw",
            textEncoder.encode(passwordField.value),
            "PBKDF2",
            false,
            ["deriveBits"] 
        ),
        256
    );

    unlockError.textContent = "";

    // import key for encryption, and compute hash for auth
    keyHash = Array.prototype.map.call(new Uint8Array(await window.crypto.subtle.digest("SHA-256", masterKeyBits)), byte => byte.toString(16).padStart(2, '0')).join("");
    masterKey = await window.crypto.subtle.importKey("raw", masterKeyBits, {"name": "AES-GCM"}, false, ["encrypt", "decrypt"]);

    initializeVault();
    unlockForm.reset();

});