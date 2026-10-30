# celld SIP PBX Example

This example demonstrates how `celld` provides enterprise-grade, serverless SIP (RFC 3261) telephony and call state management without the complexity of traditional PBX software.

## Architecture

- **Stateless PBX Worker (`default`)**:
  - Handles incoming SIP transactions across UDP (port 5060) and WebSocket (`/sip`).
  - Implements **RFC 2617 & RFC 8760 Digest Authentication** (`req.verifyDigestAuth`, `req.challengeDigestAuth`).
  - Acts as a SIP Registrar and stateless ingress router.
  - Dynamically routes in-dialog stateful transactions (`INVITE`, `BYE`, `ACK`, `CANCEL`) to dedicated `CallSession` Durable Objects.

- **CallSession Durable Object (`CallSession`)**:
  - Encapsulates Back-to-Back User Agent (B2BUA) dialog state for each unique call leg.
  - Uses `this.ctx.sip.forkInvite(req, targets)` to fork calls across registered devices.
  - Exposes `req.sendProvisional(180, "Ringing")` for zero-latency 1xx provisional signalling.
  - Bridges the winning dialog leg with `winnerLeg.bridgeTo(req)` upon 200 OK.
  - Automatically manages dialog states (`early`, `confirmed`, `terminated`) in the cell's local SQLite database (`__celld_sip_dialogs`).
  - Guarantees durability and single-writer semantics via `celld`'s Sans-I/O Output Gate.

## Configuration

In `wrangler.jsonc`:
```jsonc
{
  "name": "sip-pbx",
  "main": "index.js",
  "compatibility_date": "2026-01-01",
  "durable_objects": {
    "bindings": [{ "name": "CALL_SESSION", "class_name": "CallSession" }]
  },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["CallSession"] }],
  "sip": {
    "domain": "sip.example.com",
    "listeners": [
      { "id": "udp-5060", "protocol": "udp", "bind": "0.0.0.0:5060" },
      { "id": "ws-5060", "protocol": "ws", "bind": "0.0.0.0:8080" }
    ]
  }
}
```

## Running

Deploy or run locally with the `celld` CLI:
```bash
celld dev
```
