const API_ROOT = "passwords.bithole.dev";
const syncEndpoint = new URL("/vault/sync", API_ROOT),
      createEndpoint = new URL("/vault/create", API_ROOT);

// elements
const unlockForm = document.getElementById("unlock-form"),
      unlockError = document.getElementById("unlock-error"),
      saveError = document.getElementById("save-error"),
      vaultView = document.getElementById("vault-view"),
      passwordsTable = document.getElementById("passwords-table"),
      editorDialog = document.getElementById("editor"),
      editorForm = document.getElementById("editor-form"),
      entryName = document.getElementById("entry-name"),
      entryUsername = document.getElementById("entry-username"),
      entryEmail = document.getElementById("entry-email"),
      entryPassword = document.getElementById("entry-password"),
      entryUrl = document.getElementById("entry-url");

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
    const req = await fetch(syncEndpoint, {
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
    saveError.textContent = "";
    try {
        await encryptAndCommit();
    } catch(error) {
        console.error(error);
        saveError.textContent = "Vault could not be uploaded to remote server";
    }
};

const showVaultView = () => {
    unlockForm.style.display = "none";
    vaultView.style.display = "";
    for(const entry of vault.content.entries) {
        addEntry(entry);
    }
    refreshOrder();
};

const loadLocalVault = async () => {
    vault = await decryptVault(window.localStorage.getItem("vault"+keyHash));
    counter = Number(window.localStorage.getItem("counter"+keyHash));
};

const initializeVault = async () => {

    unlockError.textContent = "";

    // if we want to create a new vault, initialize an empty vault and try to commit it
    if(document.getElementById("create-new").checked) {
        vault = {
            iv: new Uint8Array(IV_LENGTH),
            content: {
                entries: []
            }
        };
        counter = 1;
        const encrypted = await encryptLocalVault();
        try {
            const req = await fetch(createEndpoint, {
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
            unlockError.textContent = "Failed to upload vault; it may exist already";
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
            unlockError.textContent = "Local vault is missing, try clearing the data for this site";
            return;
        }

        await commit();
        showVaultView();

    } else {

        // do a dummy sync operation; if the counter has increased since the vault was last accessed locally, then we will receive a copy of the vault
        lastCounter = Number(window.localStorage.getItem("counter"+keyHash)) || -1;
        try {

            const req = await fetch(syncEndpoint, {
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
                    unlockError.textContent = "Username or password is incorrect";
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
                saveError.textContent = "Remote server could not be reached, so the last saved copy of the vault was loaded";
            } catch(error) {
                unlockError.textContent = "Vault unlock failed";
            }

        }

    }

};

const handleUnlock = async () => {
    username = document.getElementById("username").value;

    // derive master key from password
    const masterKeyBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: "SHA-256",
            salt: textEncoder.encode("bithole-passwords" + username),
            iterations: 1_000_000
        },
        await window.crypto.subtle.importKey(
            "raw",
            textEncoder.encode(document.getElementById("password").value),
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
};

unlockForm.addEventListener("submit", event => {
    event.preventDefault();
    handleUnlock();
    return false;
});

// associate vault entries with UI elements
const tableEntries = new Map();

const refreshOrder = () => {
    
    // sort table entries lexicographically
    const sorted = vault.content.entries.sort((a, b) => a.name.localeCompare(b.name));

    for(let i = 0; i < sorted.length; i++) {
        tableEntries.get(sorted[i]).style.order = i;
    }

};

const addEntry = entry => {
    
    const elem = document.createElement("div");
    tableEntries.set(entry, elem);
    passwordsTable.append(elem);

    const serviceName = document.createElement("span");
    serviceName.classList.add("service-name");
    serviceName.textContent = entry.name;
    elem.append(serviceName);

    const copyLinkOuter = document.createElement("span");
    copyLinkOuter.classList.add("copy-link");
    const copyLink = document.createElement("a");
    copyLink.textContent = "copy";
    copyLink.href = "#";
    copyLinkOuter.append(copyLink);
    elem.append(copyLinkOuter);

    const editLinkOuter = document.createElement("span");
    editLinkOuter.classList.add("edit-link");
    const editLink = document.createElement("a");
    editLink.textContent = "edit";
    editLink.href = "#";
    editLinkOuter.append(editLink);
    elem.append(editLink);

    const deleteLinkOuter = document.createElement("span");
    deleteLinkOuter.classList.add("delete-link");
    const deleteLink = document.createElement("a");
    deleteLink.textContent = "delete";
    deleteLink.href = "#";
    deleteLinkOuter.append(deleteLink);
    elem.append(deleteLinkOuter);

    copyLink.addEventListener("click", () => {
        copyLink.style.animationName = "";
        navigator.clipboard.writeText(entry.password).then(() => {
            copyLink.style.animationName = "pulse-green";
        });
    });

    editLink.addEventListener("click", () => {
        editingEntry = entry;
        entryName.value = entry.name;
        entryUsername.value = entry.username;
        entryEmail.value = entry.email;
        entryPassword.value = entry.password;
        entryUrl.value = entry.url;
        editorDialog.showModal();
    });

    deleteLink.addEventListener("click", () => {
        if(prompt(`You are about to delete a saved password. This cannot be undone. Please retype "${entry.name}" to confirm your choice.`) != entry.name) {
            return;
        }
        vault.content.entries.splice(vault.content.entries.indexOf(entry), 1);
        tableEntries.delete(entry);
        elem.remove();
        commit();
    });

};

// modal state
let editingEntry = null;

editorDialog.addEventListener("close", () => {
    editorForm.reset();
    editingEntry = null;
});

document.getElementById("add-link").addEventListener("click", () => {
    editorDialog.showModal();
});

document.getElementById("entry-cancel").addEventListener("click", () => {
    editorDialog.close();
    editorForm.reset();
    editingEntry = null;
});

document.getElementById("autogen-password").addEventListener("click", () => {

    let password = "";
    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
    const randomValues = new Uint32Array(16);
    window.crypto.getRandomValues(randomValues);

    for(let i = 0; i < 4; i++) {
        for(let j = 0; j < 4; j++) {
            password += alphabet[randomValues[i*4+j] % 36];
        }
        if(i < 3)
            password += " ";
    }

    entryPassword.value = password;

});

editorForm.addEventListener("submit", event => {

    event.preventDefault();

    // confirm overwrite
    if(editingEntry && editingEntry.password != entryPassword.value) {
        if(prompt(`You are about to overwrite an existing password. This cannot be undone. Please retype "${editingEntry.name}" to confirm your choice.`) != editingEntry.name) {
            return;
        }
    }

    // strip url
    let url = "";
    try {
        url = new URL(entryUrl.value).origin;
    } catch(error) {
        // ignore error
    }

    if(editingEntry) {
        editingEntry.name = entryName.value;
        editingEntry.username = entryUsername.value;
        editingEntry.email = entryEmail.value;
        editingEntry.password = entryPassword.value;
        editingEntry.url = url;
        editingEntry.timestamp = Date.now();
        const entryElement = tableEntries.get(editingEntry);
        entryElement.querySelector(".service-name").textContent = entryName.value;
    } else {
        const newEntry = {
            name: entryName.value,
            username: entryUsername.value,
            email: entryEmail.value,
            password: entryPassword.value,
            url,
            timestamp: Date.now()
        }; 
        vault.content.entries.push(newEntry);
        addEntry(newEntry);
        refreshOrder();
    }

    refreshOrder();
    editorForm.reset();
    editorDialog.close();
    commit();

});