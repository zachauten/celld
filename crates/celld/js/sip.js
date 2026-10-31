// Copyright 2026 Deno Land Inc. Apache-2.0 license.

(() => {
  "use strict";

  class SipUri {
    constructor(input) {
      if (typeof input === "string") {
        this._parse(input);
      } else if (input && typeof input === "object") {
        this.scheme = input.scheme || "sip";
        this.user = input.user || null;
        this.password = input.password || null;
        this.host = input.host || "";
        this.port = input.port != null ? Number(input.port) : null;
        this.params = new Map(input.params ? Object.entries(input.params) : []);
        this.headers = new Map(input.headers ? Object.entries(input.headers) : []);
      } else {
        this.scheme = "sip";
        this.user = null;
        this.password = null;
        this.host = "";
        this.port = null;
        this.params = new Map();
        this.headers = new Map();
      }
    }

    _parse(raw) {
      let s = raw.trim();
      const colonIdx = s.indexOf(":");
      if (colonIdx === -1) {
        throw new TypeError("Invalid SIP URI: missing scheme");
      }
      this.scheme = s.slice(0, colonIdx).toLowerCase();
      if (this.scheme !== "sip" && this.scheme !== "sips") {
        throw new TypeError("Invalid SIP URI scheme: " + this.scheme);
      }
      s = s.slice(colonIdx + 1);

      // Check for headers (?)
      const qIdx = s.indexOf("?");
      let headerPart = "";
      if (qIdx !== -1) {
        headerPart = s.slice(qIdx + 1);
        s = s.slice(0, qIdx);
      }

      // Check for params (;)
      const semiSplits = s.split(";");
      const userHostPort = semiSplits[0];
      this.params = new Map();
      for (let i = 1; i < semiSplits.length; i++) {
        const p = semiSplits[i];
        if (!p) continue;
        const eq = p.indexOf("=");
        if (eq !== -1) {
          this.params.set(p.slice(0, eq).toLowerCase(), p.slice(eq + 1));
        } else {
          this.params.set(p.toLowerCase(), null);
        }
      }

      // Parse user:password@host:port
      const atIdx = userHostPort.indexOf("@");
      let hostPort = userHostPort;
      this.user = null;
      this.password = null;
      if (atIdx !== -1) {
        const userPass = userHostPort.slice(0, atIdx);
        hostPort = userHostPort.slice(atIdx + 1);
        const uColon = userPass.indexOf(":");
        if (uColon !== -1) {
          this.user = userPass.slice(0, uColon);
          this.password = userPass.slice(uColon + 1);
        } else {
          this.user = userPass;
        }
      }

      // host:port (handling IPv6 [::1]:5060)
      if (hostPort.startsWith("[")) {
        const closeB = hostPort.indexOf("]");
        if (closeB !== -1) {
          this.host = hostPort.slice(0, closeB + 1);
          const after = hostPort.slice(closeB + 1);
          if (after.startsWith(":")) {
            this.port = Number(after.slice(1));
          } else {
            this.port = null;
          }
        } else {
          this.host = hostPort;
          this.port = null;
        }
      } else {
        const pColon = hostPort.lastIndexOf(":");
        if (pColon !== -1) {
          this.host = hostPort.slice(0, pColon);
          this.port = Number(hostPort.slice(pColon + 1));
        } else {
          this.host = hostPort;
          this.port = null;
        }
      }

      this.headers = new Map();
      if (headerPart) {
        for (const item of headerPart.split("&")) {
          const eq = item.indexOf("=");
          if (eq !== -1) {
            this.headers.set(decodeURIComponent(item.slice(0, eq)), decodeURIComponent(item.slice(eq + 1)));
          } else {
            this.headers.set(decodeURIComponent(item), "");
          }
        }
      }
    }

    get userAtHost() {
      const u = this.user ? this.user + "@" : "";
      const p = this.port != null ? ":" + this.port : "";
      return u + this.host + p;
    }

    toString() {
      let out = this.scheme + ":";
      if (this.user) {
        out += this.user;
        if (this.password) {
          out += ":" + this.password;
        }
        out += "@";
      }
      out += this.host;
      if (this.port != null) {
        out += ":" + this.port;
      }
      for (const [k, v] of this.params.entries()) {
        out += ";" + k;
        if (v != null) {
          out += "=" + v;
        }
      }
      if (this.headers.size > 0) {
        out += "?";
        const parts = [];
        for (const [k, v] of this.headers.entries()) {
          parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(v));
        }
        out += parts.join("&");
      }
      return out;
    }
  }

  class SipNameAddr {
    constructor(input) {
      if (typeof input === "string") {
        this._parse(input);
      } else if (input && typeof input === "object") {
        this.displayName = input.displayName || null;
        this.uri = input.uri instanceof SipUri ? input.uri : new SipUri(input.uri);
        this.tag = input.tag || null;
        this.params = new Map(input.params ? Object.entries(input.params) : []);
      } else {
        this.displayName = null;
        this.uri = new SipUri("sip:unknown");
        this.tag = null;
        this.params = new Map();
      }
    }

    _parse(raw) {
      let s = raw.trim();
      this.displayName = null;
      this.tag = null;
      this.params = new Map();

      const lt = s.indexOf("<");
      const gt = s.indexOf(">");
      let uriStr = "";
      let paramPart = "";

      if (lt !== -1 && gt !== -1 && gt > lt) {
        const namePart = s.slice(0, lt).trim();
        if (namePart) {
          this.displayName = namePart.replace(/^["']|["']$/g, "").trim();
        }
        uriStr = s.slice(lt + 1, gt);
        paramPart = s.slice(gt + 1);
      } else {
        const semi = s.indexOf(";");
        if (semi !== -1) {
          uriStr = s.slice(0, semi).trim();
          paramPart = s.slice(semi);
        } else {
          uriStr = s.trim();
        }
      }

      this.uri = new SipUri(uriStr);

      if (paramPart) {
        for (const part of paramPart.split(";")) {
          const p = part.trim();
          if (!p) continue;
          const eq = p.indexOf("=");
          if (eq !== -1) {
            const k = p.slice(0, eq).trim().toLowerCase();
            const v = p.slice(eq + 1).trim();
            if (k === "tag") {
              this.tag = v;
            } else {
              this.params.set(k, v);
            }
          } else {
            this.params.set(p.toLowerCase(), null);
          }
        }
      }
    }

    toString() {
      let out = "";
      if (this.displayName) {
        out += `"${this.displayName}" `;
      }
      out += `<${this.uri.toString()}>`;
      if (this.tag) {
        out += `;tag=${this.tag}`;
      }
      for (const [k, v] of this.params.entries()) {
        out += ";" + k;
        if (v != null) {
          out += "=" + v;
        }
      }
      return out;
    }
  }

  class SipContact {
    constructor(input) {
      if (typeof input === "string") {
        this._parse(input);
      } else if (input && typeof input === "object") {
        this.nameAddr = input.nameAddr instanceof SipNameAddr ? input.nameAddr : new SipNameAddr(input.nameAddr || input.uri);
        this.expires = input.expires != null ? Number(input.expires) : null;
        this.q = input.q != null ? String(input.q) : null;
        this.params = new Map(input.params ? Object.entries(input.params) : []);
      } else {
        this.nameAddr = new SipNameAddr("sip:unknown");
        this.expires = null;
        this.q = null;
        this.params = new Map();
      }
    }

    _parse(raw) {
      this.nameAddr = new SipNameAddr(raw);
      this.expires = null;
      this.q = null;
      this.params = new Map();

      // Check nameAddr params for expires/q
      for (const [k, v] of this.nameAddr.params.entries()) {
        if (k === "expires") {
          this.expires = Number(v);
        } else if (k === "q") {
          this.q = v;
        } else {
          this.params.set(k, v);
        }
      }
    }

    get uri() {
      return this.nameAddr.uri;
    }

    toString() {
      let out = this.nameAddr.toString();
      if (this.expires != null) {
        out += `;expires=${this.expires}`;
      }
      if (this.q != null) {
        out += `;q=${this.q}`;
      }
      for (const [k, v] of this.params.entries()) {
        out += ";" + k;
        if (v != null) {
          out += "=" + v;
        }
      }
      return out;
    }
  }

  class SipRequest {
    constructor(dto) {
      if (typeof dto === "string") {
        dto = JSON.parse(dto);
      }
      dto = dto || {};

      this.id = dto.id_str ? dto.id_str : (dto.id != null ? String(dto.id) : (dto._requestId != null ? String(dto._requestId) : "0"));
      this._requestId = this.id;
      this.method = dto.method || "INVITE";
      this.uri = new SipUri(dto.uri || "sip:unknown");
      this.version = dto.version || "SIP/2.0";
      this.callId = dto.call_id || dto.callId || "";
      this.cseq = {
        num: dto.cseq_num != null ? dto.cseq_num : (dto.cseq && dto.cseq.num != null ? dto.cseq.num : 1),
        method: dto.cseq_method || (dto.cseq && dto.cseq.method ? dto.cseq.method : this.method),
      };
      this.from = new SipNameAddr(dto.from || "sip:unknown");
      this.to = new SipNameAddr(dto.to || "sip:unknown");
      this.contacts = Array.isArray(dto.contacts)
        ? dto.contacts.map((c) => new SipContact(c))
        : [];
      this.maxForwards = dto.max_forwards != null ? dto.max_forwards : (dto.maxForwards != null ? dto.maxForwards : 70);
      this.expires = dto.expires != null ? dto.expires : null;

      this.headers = new Headers(dto.headers || []);
      if (dto.body instanceof Uint8Array) {
        this.body = dto.body;
      } else if (Array.isArray(dto.body)) {
        this.body = new Uint8Array(dto.body);
      } else if (typeof dto.body === "string") {
        this.body = new TextEncoder().encode(dto.body);
      } else {
        this.body = new Uint8Array(0);
      }

      this.transport = {
        protocol: dto.transport_protocol || (dto.transport && dto.transport.protocol) || "udp",
        sourceAddress: dto.source_address || (dto.transport && dto.transport.sourceAddress) || "",
        destinationAddress: dto.destination_address || (dto.transport && dto.transport.destinationAddress) || null,
        nodeId: dto.node_id || (dto.transport && dto.transport.nodeId) || "",
        listenerId: dto.listener_id || (dto.transport && dto.transport.listenerId) || null,
      };
    }

    toJSON() {
      return {
        id: this._requestId,
        id_str: this._requestId,
        method: this.method,
        uri: this.uri.toString(),
        version: this.version,
        call_id: this.callId,
        cseq_num: this.cseq.num,
        cseq_method: this.cseq.method,
        from: this.from.toString(),
        to: this.to.toString(),
        contacts: this.contacts.map((c) => c.toString()),
        max_forwards: this.maxForwards,
        expires: this.expires,
        headers: Array.from(this.headers.entries()),
        body: Array.from(this.body),
        transport_protocol: this.transport.protocol,
        source_address: this.transport.sourceAddress,
        destination_address: this.transport.destinationAddress,
        node_id: this.transport.nodeId,
        listener_id: this.transport.listenerId,
      };
    }

    text() {
      return new TextDecoder().decode(this.body);
    }

    sendProvisional(status, reason = "", options = {}) {
      if (status < 100 || status > 199) {
        throw new RangeError("Provisional SIP status must be in range 100-199: " + status);
      }
      const hdrs = [];
      if (options.headers && typeof options.headers.entries === "function") {
        for (const [k, v] of options.headers.entries()) {
          hdrs.push([k, v]);
        }
      } else if (Array.isArray(options.headers)) {
        for (const item of options.headers) {
          hdrs.push(item);
        }
      }
      const contacts = Array.isArray(options.contacts)
        ? options.contacts.map((c) => (typeof c === "string" ? c : c.toString()))
        : [];

      let bodyBytes = null;
      if (options.body instanceof Uint8Array) {
        bodyBytes = options.body;
      } else if (typeof options.body === "string") {
        bodyBytes = new TextEncoder().encode(options.body);
      }

      const headersJson = JSON.stringify(hdrs);
      const contactsJson = JSON.stringify(contacts);

      const op = __celld.__sip_send_provisional;
      if (typeof op === "function") {
        op(this._requestId, status, reason, headersJson, contactsJson, bodyBytes);
      } else {
        throw new Error("__sip_send_provisional op not bound");
      }
    }

    verifyDigestAuth(options = {}) {
      const realm = options.realm || "celld";
      const algorithm = options.algorithm || "MD5";
      const qop = options.qop !== false;

      const authHdr =
        this.headers.get("authorization") ||
        this.headers.get("proxy-authorization");

      if (!authHdr) {
        const nonce = (Date.now().toString(16) + Math.random().toString(16).slice(2)).slice(0, 32);
        const challenge = __celld.__sip_generate_challenge
          ? __celld.__sip_generate_challenge(realm, nonce, algorithm, qop)
          : `Digest realm="${realm}", nonce="${nonce}", algorithm=${algorithm}${qop ? ', qop="auth"' : ""}`;

        return {
          verified: false,
          challenge,
          challengeResponse: (status = 401) => {
            const hName = status === 407 ? "Proxy-Authenticate" : "WWW-Authenticate";
            const reason = status === 407 ? "Proxy Authentication Required" : "Unauthorized";
            return new SipResponse(status, reason, {
              headers: [[hName, challenge]],
            });
          },
        };
      }

      // Parse username from header
      let username = "";
      const userMatch = authHdr.match(/username\s*=\s*["']?([^"',]+)["']?/i);
      if (userMatch) {
        username = userMatch[1];
      }

      let ha1 = "";
      if (options.password) {
        ha1 = __celld.__sip_compute_ha1
          ? __celld.__sip_compute_ha1(algorithm, username, realm, options.password)
          : "";
      } else if (typeof options.getPasswordHash === "function") {
        ha1 = options.getPasswordHash(username, realm) || "";
      }

      const verified = __celld.__sip_digest_verify
        ? __celld.__sip_digest_verify(authHdr, this.method, ha1)
        : false;

      return {
        verified,
        username,
        realm,
        challengeResponse: (status = 401) => {
          const nonce = (Date.now().toString(16) + Math.random().toString(16).slice(2)).slice(0, 32);
          const challenge = __celld.__sip_generate_challenge
            ? __celld.__sip_generate_challenge(realm, nonce, algorithm, qop)
            : `Digest realm="${realm}", nonce="${nonce}", algorithm=${algorithm}${qop ? ', qop="auth"' : ""}`;
          const hName = status === 407 ? "Proxy-Authenticate" : "WWW-Authenticate";
          const reason = status === 407 ? "Proxy Authentication Required" : "Unauthorized";
          return new SipResponse(status, reason, {
            headers: [[hName, challenge]],
          });
        },
      };
    }
  }

  class SipResponse {
    constructor(status = 200, reason = "OK", init = {}) {
      this.status = Number(status);
      this.reason = String(reason || (this.status === 200 ? "OK" : ""));
      this.headers = new Headers(init.headers || []);
      this.contacts = Array.isArray(init.contacts)
        ? init.contacts.map((c) => (typeof c === "string" ? c : c.toString()))
        : [];

      if (init.body instanceof Uint8Array) {
        this.body = init.body;
      } else if (Array.isArray(init.body)) {
        this.body = new Uint8Array(init.body);
      } else if (typeof init.body === "string") {
        this.body = new TextEncoder().encode(init.body);
      } else {
        this.body = new Uint8Array(0);
      }
    }

    text() {
      return new TextDecoder().decode(this.body);
    }

    json() {
      return JSON.parse(this.text());
    }
  }

  // Bind response reader for the Rust host
  __celld.__readSipResponse = (ret) => {
    if (!ret || typeof ret !== "object") {
      throw new TypeError("SIP handler must return a SipResponse object");
    }
    const status = ret.status != null ? Number(ret.status) : 200;
    const reason = String(ret.reason || (status === 200 ? "OK" : ""));
    const headers = [];
    if (ret.headers && typeof ret.headers.entries === "function") {
      for (const [k, v] of ret.headers.entries()) {
        headers.push([k, v]);
      }
    } else if (Array.isArray(ret.headers)) {
      for (const item of ret.headers) {
        headers.push(item);
      }
    }
    const contacts = Array.isArray(ret.contacts)
      ? ret.contacts.map((c) => (typeof c === "string" ? c : c.toString()))
      : [];

    let bodyBytes = null;
    if (ret.body instanceof Uint8Array) {
      bodyBytes = ret.body;
    } else if (typeof ret.body === "string") {
      bodyBytes = new TextEncoder().encode(ret.body);
    } else if (Array.isArray(ret.body)) {
      bodyBytes = new Uint8Array(ret.body);
    } else {
      bodyBytes = new Uint8Array(0);
    }

    return {
      status,
      reason,
      headersJson: JSON.stringify(headers),
      contactsJson: JSON.stringify(contacts),
      bodyBytes,
    };
  };

  // Bind entrypoint SIP dispatcher
  __celld.__dispatchEntrypointSip = (name, reqJson) => {
    const req = new SipRequest(reqJson);
    return __celld.__dispatchEntrypointMethod(name, "sip", req);
  };

  class SipLeg {
    constructor(ctx, data) {
      this.ctx = ctx;
      this.dialogId = data.dialogId;
      this.callId = data.callId;
      this.localTag = data.localTag;
      this.remoteTag = data.remoteTag || null;
      this.localUri = data.localUri;
      this.remoteUri = data.remoteUri;
      this.state = data.state || "early";
      this.sdp = data.sdp || null;
      this.target = data.target || data.remoteUri;
    }

    bridgeTo(callerReq, options = {}) {
      return this.ctx._bridgeLegs(callerReq, this, options);
    }

    terminate() {
      return this.ctx._terminateLeg(this.dialogId);
    }
  }

  class CellSipContext {
    constructor(state) {
      this._state = state;
      this._initialized = false;
    }

    _ensureTable() {
      if (this._initialized) return;
      if (this._state && this._state.storage && this._state.storage.sql) {
        try {
          this._state.storage.sql.exec(`
            CREATE TABLE IF NOT EXISTS __celld_sip_dialogs (
              dialog_id TEXT PRIMARY KEY,
              call_id TEXT NOT NULL,
              local_tag TEXT NOT NULL,
              remote_tag TEXT,
              local_uri TEXT NOT NULL,
              remote_uri TEXT NOT NULL,
              local_seq INTEGER NOT NULL DEFAULT 1,
              remote_seq INTEGER NOT NULL DEFAULT 1,
              paired_dialog_id TEXT,
              state TEXT NOT NULL,
              sdp TEXT,
              created_at INTEGER NOT NULL
            )
          `);
          this._initialized = true;
        } catch (_) {}
      }
    }

    forkInvite(incomingReq, targets, options = {}) {
      this._ensureTable();
      const callerCallId = incomingReq.callId;
      const callerFrom = incomingReq.from;
      const callerDialogId = `${callerCallId}:in`;

      if (this._state && this._state.storage && this._state.storage.sql) {
        try {
          this._state.storage.sql.exec(
            `INSERT OR REPLACE INTO __celld_sip_dialogs
             (dialog_id, call_id, local_tag, remote_tag, local_uri, remote_uri, state, sdp, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 'early', ?, ?)`,
            callerDialogId,
            callerCallId,
            "srv-" + Math.random().toString(36).slice(2, 10),
            incomingReq.fromTag || "",
            incomingReq.to || "",
            incomingReq.from || "",
            typeof incomingReq.body === "string" ? incomingReq.body : null,
            Date.now()
          );
        } catch (_) {}
      }

      const legs = [];
      for (let i = 0; i < targets.length; i++) {
        const target = targets[i];
        const legCallId = `${callerCallId}-fork-${i + 1}`;
        const localTag = "leg-" + Math.random().toString(36).slice(2, 10);
        const legDialogId = `${legCallId}:${localTag}`;

        const leg = new SipLeg(this, {
          dialogId: legDialogId,
          callId: legCallId,
          localTag,
          remoteTag: null,
          localUri: callerFrom,
          remoteUri: target,
          state: "early",
          sdp: typeof incomingReq.body === "string" ? incomingReq.body : null,
          target,
        });

        if (this._state && this._state.storage && this._state.storage.sql) {
          try {
            this._state.storage.sql.exec(
              `INSERT OR REPLACE INTO __celld_sip_dialogs
               (dialog_id, call_id, local_tag, remote_tag, local_uri, remote_uri, state, sdp, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 'early', ?, ?)`,
              legDialogId,
              legCallId,
              localTag,
              null,
              callerFrom,
              target,
              leg.sdp,
              Date.now()
            );
          } catch (_) {}
        }
        legs.push(leg);
      }

      return legs;
    }

    _bridgeLegs(callerReq, winnerLeg, options = {}) {
      this._ensureTable();
      const callerCallId = callerReq.callId;
      const callerDialogId = `${callerCallId}:in`;

      winnerLeg.state = "confirmed";
      if (options.remoteTag) {
        winnerLeg.remoteTag = options.remoteTag;
      }
      if (options.sdp) {
        winnerLeg.sdp = options.sdp;
      }

      if (this._state && this._state.storage && this._state.storage.sql) {
        try {
          this._state.storage.sql.exec(
            `UPDATE __celld_sip_dialogs SET paired_dialog_id = ?, state = 'confirmed', sdp = COALESCE(?, sdp) WHERE dialog_id = ?`,
            winnerLeg.dialogId,
            options.callerSdp || null,
            callerDialogId
          );
          this._state.storage.sql.exec(
            `UPDATE __celld_sip_dialogs SET paired_dialog_id = ?, state = 'confirmed', remote_tag = COALESCE(?, remote_tag), sdp = COALESCE(?, sdp) WHERE dialog_id = ?`,
            callerDialogId,
            winnerLeg.remoteTag,
            winnerLeg.sdp,
            winnerLeg.dialogId
          );
          this._state.storage.sql.exec(
            `UPDATE __celld_sip_dialogs SET state = 'terminated' WHERE call_id LIKE ? AND dialog_id != ? AND dialog_id != ?`,
            `${callerCallId}-fork-%`,
            winnerLeg.dialogId,
            callerDialogId
          );
        } catch (_) {}
      }

      const respHeaders = options.headers || [];
      return new SipResponse(200, "OK", {
        headers: respHeaders,
        body: winnerLeg.sdp || callerReq.body,
      });
    }

    terminatePairedLeg(req) {
      this._ensureTable();
      const callId = req.callId;
      let paired = null;

      if (this._state && this._state.storage && this._state.storage.sql) {
        try {
          const rows = this._state.storage.sql.exec(
            `SELECT paired_dialog_id FROM __celld_sip_dialogs WHERE call_id = ?`,
            callId
          ).toArray();
          if (rows.length > 0 && rows[0].paired_dialog_id) {
            const pairedId = rows[0].paired_dialog_id;
            const pairedRows = this._state.storage.sql.exec(
              `SELECT * FROM __celld_sip_dialogs WHERE dialog_id = ?`,
              pairedId
            ).toArray();
            if (pairedRows.length > 0) {
              paired = pairedRows[0];
            }
          }
          this._state.storage.sql.exec(
            `UPDATE __celld_sip_dialogs SET state = 'terminated' WHERE call_id = ? OR paired_dialog_id = ?`,
            callId,
            callId
          );
        } catch (_) {}
      }

      return paired;
    }

    _terminateLeg(dialogId) {
      this._ensureTable();
      if (this._state && this._state.storage && this._state.storage.sql) {
        try {
          this._state.storage.sql.exec(
            `UPDATE __celld_sip_dialogs SET state = 'terminated' WHERE dialog_id = ?`,
            dialogId
          );
        } catch (_) {}
      }
    }
  }

  // Expose to global scope
  globalThis.SipUri = SipUri;
  globalThis.SipNameAddr = SipNameAddr;
  globalThis.SipContact = SipContact;
  globalThis.SipRequest = SipRequest;
  globalThis.SipResponse = SipResponse;
  globalThis.SipLeg = SipLeg;
  globalThis.CellSipContext = CellSipContext;
})();
