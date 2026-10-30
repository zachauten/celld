# Serverless SIP in `celld`: High-Level Architecture & Plan

> [!NOTE]
> This document outlines the high-level architecture and design concepts for SIP support in `celld`. For the detailed, phased engineering roadmap with test verification, see the [SIP Test-Driven Implementation Plan](sip-implementation-plan.md).

Adding **SIP (Session Initiation Protocol, RFC 3261)** support to **`denoland/celld`** is a natural architectural fit. Traditional SIP infrastructure (Kamailio, OpenSIPS, Asterisk, FreeSWITCH) struggles with horizontal scaling and state synchronization because SIP is inherently stateful across multiple timescales: **Transactions** (milliseconds to seconds), **Dialogs/Calls** (minutes to hours), and **Registrations/Presence** (hours to days).

Because `celld` combines stateless V8 Workers with stateful, SQLite-backed **Durable Objects (Cells)** coordinated via S3 leases and peer-to-peer tunnels, you can map SIP's stateful primitives directly onto `celld` cells.

---

## 1. High-Level Architecture & Implementation Plan

To bring SIP to `celld` without breaking its serverless model (where V8 isolates spin down/hibernate when idle), the Rust daemon should handle the low-level transport and RFC 3261 transaction state machine, while exposing high-level SIP events to JavaScript.

```
                     UDP / TCP / TLS / WSS (SIP)
                                  │
                                  ▼
┌───────────────────────────────────────────────────────────────────┐
│                         celld Node (Rust)                         │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ 1. SIP Transport & Transaction Layer (Rust / Tokio)         │  │
│  │  - Socket Listeners (UDP 5060, TCP/TLS 5061, WS/WSS)        │  │
│  │  - RFC 3261 Parser & Transaction State Machine (Timers A-K) │  │
│  │  - Automatic 100 Trying & Retransmission Deduplication      │  │
│  └──────────────────────────────┬──────────────────────────────┘  │
│                                 │                                 │
│                                 ▼                                 │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │ 2. Stateless Worker Isolate (V8)                            │  │
│  │  - Entrypoint: `sip(request, env, ctx)`                     │  │
│  │  - Auth checks, header manipulation, routing to DO Cells    │  │
│  └───────────────┬─────────────────────────────┬───────────────┘  │
│                  │ Local Cell                  │ Remote Cell      │
│                  ▼                             ▼ (HMAC Peer Tunnel)
│  ┌──────────────────────────────┐   ┌──────────────────────────┐  │
│  │ 3. Durable Object Cell       │   │ Peer celld Node          │  │
│  │  - Dialog / Registrar State  │   │  - Owns target Cell      │  │
│  │  - Embedded SQLite + Alarms  │   │  - Sends SIP egress via  │  │
│  │  - Media / RTP Sidecar Hook  │   │    originating node      │  │
│  └──────────────────────────────┘   └──────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

### Phase 1: Rust SIP Transport & Transaction Layer
* **Transport Listeners:** Extend `celld`'s listener configuration to bind UDP, TCP, TLS, and WebSocket (`sip` subprotocol, RFC 7118) sockets alongside its HTTP listeners.
* **Rust Transaction Layer:** Embed a Rust SIP stack (e.g., building on `rsip` or `sipcore` + Tokio) inside `celld`.
  * **Why in Rust?** SIP over UDP requires strict retransmission timers (Timer A, B, E, F, G, H, I, J, K). If a JavaScript isolate had to wake up for every UDP packet retransmission, it would waste CPU. The Rust layer absorbs retransmissions, sends automatic `100 Trying` when configured, and only invokes the V8 isolate once per *logical* SIP transaction or dialog event.
* **NAT Pinholes & Outbound (RFC 5626):** Because `celld` runs across multiple nodes, a NATted SIP client that registered via Node A must receive incoming `INVITE`s from Node A's IP/port (or connection ID). When a Cell on Node B sends a SIP request to that client, `celld` should route the egress packet over its existing **peer-to-peer HMAC tunnel** back to Node A's socket.

### Phase 2: V8 Bindings & `SipRequest` / `SipResponse` Primitives
* Mirror the Web Fetch API (`Request` / `Response`) with web-idiomatic `SipRequest` and `SipResponse` classes in the V8 runtime.
* Provide built-in helpers for **Digest Authentication** (`WWW-Authenticate` / `Authorization` MD5/SHA-256 challenge verification), **SDP parsing/manipulation**, and **Record-Route / Via** header management so JS code doesn't have to manually construct fragile SIP headers.

### Phase 3: Stateful SIP Primitives on Durable Objects (Cells)
* Add `cell.sip(...)` RPC dispatch alongside `cell.fetch(...)` so Workers can forward a `SipRequest` directly into a Durable Object instance.
* Integrate **Dialog/B2BUA primitives** into the `DurableObjectState` (`ctx.sip`) so a Cell can act as a Proxy, Registrar, or Back-to-Back User Agent (B2BUA) that bridges two SIP legs while hibernating between in-dialog requests (`BYE`, `re-INVITE`, `INFO`).

### Phase 4: Media Plane Control (RTP/WebRTC Sidecar API)
* SIP is only signaling; voice/video media flows over RTP/SRTP. Rather than forcing RTP packets through V8, `celld` can include a built-in Rust media relay (or control an external `rtpengine` instance via its ng control protocol) exposed to JS as `env.MEDIA` or `ctx.sip.media`.

---

## 2. JavaScript API & Server Configuration

### Configuration (`wrangler.jsonc`)
Extend the `celld` configuration to declare SIP listeners and bind Durable Objects:

```jsonc
{
  "name": "serverless-pbx",
  "main": "src/index.ts",
  "compatibility_date": "2026-10-01",
  "sip": {
    "domains": ["sip.example.com"],
    "listeners": [
      { "protocol": "udp", "port": 5060 },
      { "protocol": "tcp", "port": 5060 },
      { "protocol": "tls", "port": 5061, "cert": "./certs/fullchain.pem", "key": "./certs/privkey.pem" },
      { "protocol": "ws",  "port": 8080, "path": "/sip" }
    ],
    "auto_100_trying": true
  },
  "durable_objects": {
    "bindings": [
      { "name": "REGISTRAR", "class_name": "SipRegistrar" },
      { "name": "CALL_SESSION", "class_name": "CallSession" }
    ]
  }
}
```

### Stateless Edge Worker API (`sip()` Handler)
The stateless Worker acts like a Kamailio routing block—inspecting headers, rejecting spam, authenticating users, and routing to Durable Objects:

```typescript
export default {
  async sip(req: SipRequest, env: Env, ctx: ExecutionContext): Promise<SipResponse> {
    // 1. Handle keep-alive pings immediately at the edge
    if (req.method === "OPTIONS") {
      return new SipResponse(200, "OK");
    }

    // 2. Route REGISTER requests to a Durable Object keyed by the user's Address of Record (AoR)
    if (req.method === "REGISTER") {
      const aor = req.to.uri.userAtHost; // e.g., "alice@sip.example.com"
      const id = env.REGISTRAR.idFromName(aor);
      return env.REGISTRAR.get(id).sip(req);
    }

    // 3. Route INVITE / BYE / ACK / CANCEL to a CallSession Durable Object keyed by Call-ID
    if (["INVITE", "ACK", "BYE", "CANCEL", "INFO", "REFER"].includes(req.method)) {
      const id = env.CALL_SESSION.idFromName(req.callId);
      return env.CALL_SESSION.get(id).sip(req);
    }

    return new SipResponse(405, "Method Not Allowed");
  }
};
```

### Durable Object API (`SipRegistrar` & `CallSession`)

#### A. User Registration & Presence (`SipRegistrar` Cell)
Each user (`alice@sip.example.com`) gets their own isolated SQLite-backed Cell:

```typescript
import { DurableObject } from "cloudflare:workers";

export class SipRegistrar extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS bindings (
        contact_uri TEXT PRIMARY KEY,
        edge_node_id TEXT,
        received_addr TEXT,
        expires_at INTEGER,
        user_agent TEXT
      )
    `);
  }

  async sip(req: SipRequest): Promise<SipResponse> {
    // 1. Built-in Digest Auth helper
    const auth = await req.verifyDigestAuth({
      realm: "sip.example.com",
      getPasswordHash: async (username) => this.env.USERS_KV.get(`ha1:${username}`)
    });
    if (!auth.verified) {
      return auth.challengeResponse(401); // Generates 401 with nonce
    }

    // 2. Upsert or remove Contact bindings in local SQLite
    const now = Date.now();
    for (const contact of req.contacts) {
      const expires = contact.expires ?? req.expires ?? 3600;
      if (expires === 0) {
        this.ctx.storage.sql.exec(`DELETE FROM bindings WHERE contact_uri = ?`, contact.uri.toString());
      } else {
        this.ctx.storage.sql.exec(
          `INSERT OR REPLACE INTO bindings VALUES (?, ?, ?, ?, ?)`,
          contact.uri.toString(),
          req.transport.nodeId,        // Which celld node holds the NAT pinhole / WS socket
          req.transport.sourceAddress, // For NAT traversal (received/rport)
          now + expires * 1000,
          req.headers.get("User-Agent")
        );
      }
    }

    // 3. Schedule DO alarm to prune expired registrations
    await this.ctx.storage.setAlarm(now + 60_000);

    const activeContacts = this.ctx.storage.sql
      .exec(`SELECT contact_uri, expires_at FROM bindings WHERE expires_at > ?`, now)
      .toArray();

    return new SipResponse(200, "OK", {
      contacts: activeContacts.map(c => ({
        uri: c.contact_uri,
        expires: Math.round((c.expires_at - now) / 1000)
      }))
    });
  }

  // RPC method callable by CallSession cells to look up where to reach this user
  async getActiveContacts() {
    return this.ctx.storage.sql
      .exec(`SELECT * FROM bindings WHERE expires_at > ?`, Date.now())
      .toArray();
  }
}
```

#### B. Stateful Call / B2BUA (`CallSession` Cell)
A `CallSession` Cell manages a live call, forks `INVITE`s to registered devices, and hibernates once the call is connected:

```typescript
export class CallSession extends DurableObject<Env> {
  async sip(req: SipRequest): Promise<SipResponse> {
    if (req.method === "INVITE") {
      const targetAor = req.to.uri.userAtHost;
      const registrar = this.env.REGISTRAR.get(this.env.REGISTRAR.idFromName(targetAor));
      const contacts = await registrar.getActiveContacts();

      if (contacts.length === 0) {
        return new SipResponse(480, "Temporarily Unavailable");
      }

      // Send provisional 180 Ringing upstream
      await req.sendProvisional(180, "Ringing");

      // Parallel fork INVITE to all registered devices (first to 200 OK wins, others auto-CANCELed)
      const winnerLeg = await this.ctx.sip.forkInvite(req, contacts.map(c => ({
        uri: c.contact_uri,
        routeViaNode: c.edge_node_id,
        destinationAddress: c.received_addr
      })), { timeoutMs: 25_000 });

      if (!winnerLeg) {
        return new SipResponse(486, "Busy Here");
      }

      // Persist dialog state in SQLite so the isolate can hibernate during the call!
      this.ctx.storage.sql.exec(
        `INSERT INTO call_log (call_id, caller, callee, started_at) VALUES (?, ?, ?, ?)`,
        req.callId, req.from.uri.toString(), targetAor, Date.now()
      );

      // Set session timer alarm (RFC 4028) to check if call is still alive in 15 mins
      await this.ctx.storage.setAlarm(Date.now() + 15 * 60_000);

      // Bridge the dialogs; celld tracks the B2BUA mapping and hibernates the V8 isolate
      return winnerLeg.bridgeTo(req);
    }

    if (req.method === "BYE") {
      // Wake from hibernation, forward BYE to the paired leg, and write CDR
      await this.ctx.sip.terminatePairedLeg(req);
      this.ctx.storage.sql.exec(
        `UPDATE call_log SET ended_at = ? WHERE call_id = ?`,
        Date.now(), req.callId
      );
      return new SipResponse(200, "OK");
    }

    return new SipResponse(200, "OK");
  }
}
```

---

## 3. How Durable Objects ("Cells") Transform SIP Architecture

In traditional VoIP stacks, scaling requires shared Redis clusters, database locks, or fragile consistent-hashing SIP load balancers. In `celld`, **every stateful SIP concept maps cleanly to a Cell**:

| SIP Concept | Durable Object Key (`idFromName`) | Role of the Cell & SQLite State |
| :--- | :--- | :--- |
| **Registrar / Location Service** | `aor` (e.g. `alice@domain.com`) | Stores all registered `Contact` bindings, WebSocket/NAT flow tokens, Presence (`PUBLISH`/`SUBSCRIBE` PIDF state), and Voicemail MWI (`NOTIFY`) subscriptions for that specific user. Zero lock contention across users. |
| **Call / Dialog State** | `Call-ID` header | Holds the state of an active call, B2BUA leg mappings, CDR (Call Detail Record) metrics, and in-call DTMF state. **Hibernates in ~4MB or swaps to disk** while users talk for an hour, waking up only on `re-INVITE`, `INFO`, or `BYE`. |
| **Conference Room / Bridge** | `room-id` | Coordinates multi-party audio/video mixers, participant mute/unmute state, and active speaker events. |
| **Call Queue / Ring Group** | `tenant:support-queue` | Tracks available agents, caller wait positions, SLA timers (via DO Alarms), and round-robin/longest-idle routing in real time. |
| **Trunk Rate Limiter** | `trunk:customer-123` | Enforces Concurrent Call Paths (CPS / max channels) and prepaid credit balances atomically in memory + SQLite without race conditions. |

**Why Hibernation + S3 LTX Replication is a Superpower for SIP:**
A standard voice call lasts 3–5 minutes where **zero SIP packets** are exchanged between the `ACK` (call start) and `BYE` (call end). In `celld`, once the `ACK` is processed, the `CallSession` cell replicates its SQLite transaction to S3 and can completely hibernate its V8 isolate. Even if the `celld` node hosting that call crashes mid-call, another node can claim the cell's S3 lease on the `BYE` packet, restore the SQLite dialog state, and tear down the call and billing record cleanly.

---

## 4. Interesting Use Cases

1. **AI Voice Agents at the Edge (SIP-to-WebSocket Bridge)**
   * Connect any standard SIP trunk (Twilio, Telnyx, carrier SBC) directly to a `celld` node.
   * When an `INVITE` arrives, a `CallSession` Durable Object answers the call, spins up an RTP-to-WebSocket audio stream, and pipes PCM/mu-law audio directly into an LLM Realtime API (OpenAI Realtime, Gemini Live, Deepgram).
   * The Durable Object's SQLite database stores the conversation transcript, tool-call state, and customer context, and can trigger a SIP `REFER` (warm transfer) to a human agent when requested.

2. **Multi-Tenant Serverless Cloud PBX ("Twilio / Jambonz in a Box")**
   * Every customer/tenant writes their own JavaScript Worker or visual call flow that compiles to a Worker bundle.
   * Tenants are completely isolated inside V8 sandboxes, and each tenant's call queues, IVR state machines, and voicemail boxes live in their own SQLite Cells backed by S3.

3. **Programmable WebRTC-to-SIP Gateway**
   * Browser clients connect via SIP-over-WebSocket (using `SIP.js` or `JsSIP`) directly to `celld`, while legacy desk phones (Polycom, Yealink) connect via UDP/TLS.
   * The `SipRegistrar` cell tracks both WebSocket and UDP contacts for the same user and forks incoming calls to both their browser tab and desk phone simultaneously.

4. **Prepaid Carrier Routing & Fraud Firewall**
   * High-throughput wholesale SIP routing often suffers from toll fraud because billing databases lag behind call setup.
   * A `TenantAccount` Durable Object can hold a customer's real-time balance in memory/SQLite, authorize `INVITE`s at sub-millisecond latency, decrement balances using Durable Object **Alarms** every 6 seconds during active calls, and immediately issue a `BYE` to all active `CallSession` cells the moment credit hits `$0.00`.
