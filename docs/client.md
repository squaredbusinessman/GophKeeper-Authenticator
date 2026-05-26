# Client

The project provides two clients:

- `gophkeeper-cli` for command-line workflows.
- `gophkeeper-tui` for interactive terminal workflows.

Both clients keep the vault key on the client side and send only encrypted metadata and payloads to the server.

## Binary Restore

Binary secrets preserve the original uploaded file name in the encrypted payload. During restore, the user chooses an output directory and the client writes the file using that stored name.

The client refuses to overwrite an existing file in the selected directory.
