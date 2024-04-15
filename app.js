// database
const Database = require("better-sqlite3");
const db = new Database("password-manager.db");

db.exec(`CREATE TABLE IF NOT EXISTS vaults (
    username TEXT PRIMARY KEY,
    keyHash TEXT NOT NULL,
    vault TEXT NOT NULL,
    counter INTEGER NOT NULL
)`);

const getVaultStmt = db.prepare("SELECT vault, counter FROM vaults WHERE username = ? AND keyHash = ?");
const getVaultByUsernameStmt = db.prepare("SELECT counter FROM vaults WHERE username = ?");
const updateVaultStmt = db.prepare("UPDATE vaults SET vault = ?, counter = ? WHERE username = ?");
const createVaultStmt = db.prepare("INSERT INTO vaults (username, keyHash, vault, counter) VALUES (?, ?, ?, ?)");

// webapp
const express = require("express");
const app = express();

if(process.env.SERVE_APP) {
    app.use(express.static("static"));
}
app.use("/vault", express.json());

app.post("/vault/sync", (req, res) => {

    const username = String(req.body.username),
          counter = Number(req.body.counter),
          newVault = String(req.body.vault),
          keyHash = String(req.body.keyHash);

    // check if the requested vault exists
    const vault = getVaultStmt.get(username, keyHash);
    if(vault) {

        // if the requester is trying to update a stale vault, fail and send the current vault
        if(counter != vault.counter) {
            res.status(400).json({
                conflict: true,
                latestVault: vault.vault,
                counter: vault.counter
            });
        } else {
            if(req.body.vault) {
                updateVaultStmt.run(newVault, counter + 1, username);
            }
            res.sendStatus(200);
        }

    } else {
        res.sendStatus(404);
    }

});

app.post("/vault/create", (req, res) => {

    const username = String(req.body.username),
          newVault = String(req.body.vault),
          keyHash = String(req.body.keyHash); 

    const vault = getVaultByUsernameStmt.get(username);
    if(vault) {
        res.sendStatus(400);
        return;
    }

    createVaultStmt.run(username, keyHash, newVault, 1);
    res.sendStatus(200);

});

app.listen(80, () => console.log("Listening"));