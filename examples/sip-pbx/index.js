import { DurableObject } from "cloudflare:workers";

/**
 * CallSession Durable Object.
 * Manages stateful SIP dialogs, B2BUA bridging, and SQLite dialog ledger.
 */
export class CallSession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
  }

  async sip(req) {
    switch (req.method) {
      case "INVITE": {
        // Step 1: Send 180 Ringing provisional response to caller
        req.sendProvisional(180, "Ringing");

        // Step 2: Fork INVITE to target destinations
        const calleeUri = "sip:bob@192.0.2.20:5060";
        const legs = this.ctx.sip.forkInvite(req, [calleeUri]);
        const winner = legs[0];

        // Step 3: Callee answers 200 OK with their SDP, bridge the legs
        const sdpAnswer = "v=0\r\no=bob 2 2 IN IP4 192.0.2.20\r\ns=Call\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";
        return winner.bridgeTo(req, {
          remoteTag: "bob-tag-123",
          sdp: sdpAnswer,
        });
      }

      case "BYE": {
        // Terminate paired B2BUA dialog leg in SQLite
        this.ctx.sip.terminatePairedLeg(req);
        return new SipResponse(200, "OK");
      }

      case "ACK":
      case "CANCEL":
        return new SipResponse(200, "OK");

      default:
        return new SipResponse(405, "Method Not Allowed");
    }
  }

  async fetch(request) {
    // Inspection endpoint: return persisted dialogs from cell SQLite
    let dialogs = [];
    try {
      dialogs = this.ctx.storage.sql
        .exec("SELECT * FROM __celld_sip_dialogs")
        .toArray();
    } catch (_) {}
    return Response.json({ callId: this.ctx.id.name, dialogs });
  }
}

/**
 * Stateless PBX Worker.
 * Handles SIP Registrations, Digest Authentication, and DO Ingress Routing.
 */
export default {
  async sip(req, env, ctx) {
    switch (req.method) {
      case "REGISTER": {
        // Enforce RFC 2617 / RFC 8760 Digest Authentication
        const realm = "sip.example.com";
        const auth = req.verifyDigestAuth({
          realm,
          lookupUser: (username) => {
            if (username === "alice") {
              return { password: "supersecretpassword" };
            }
            return null;
          },
        });

        if (!auth.authenticated) {
          const challenge = req.challengeDigestAuth({ realm });
          return new SipResponse(401, "Unauthorized", {
            headers: [["WWW-Authenticate", challenge]],
          });
        }

        // Authenticated 200 OK registration response
        return new SipResponse(200, "OK", {
          headers: [
            ["X-Authenticated-User", auth.username],
            ["Contact", req.headers.get("Contact") || ""],
            ["Expires", "3600"],
          ],
        });
      }

      case "INVITE":
      case "BYE":
      case "ACK":
      case "CANCEL": {
        // Route stateful SIP dialog to CallSession Durable Object
        const id = env.CALL_SESSION.idFromName(req.callId);
        return env.CALL_SESSION.get(id).sip(req);
      }

      case "OPTIONS":
        return new SipResponse(200, "OK", {
          headers: [["Allow", "INVITE, ACK, CANCEL, BYE, REGISTER, OPTIONS"]],
        });

      default:
        return new SipResponse(405, "Method Not Allowed");
    }
  },

  async fetch(request, env, ctx) {
    return Response.json({
      service: "sip-pbx",
      status: "healthy",
      domain: "sip.example.com",
      listeners: ["udp:5060", "ws:8080"],
    });
  },
};
