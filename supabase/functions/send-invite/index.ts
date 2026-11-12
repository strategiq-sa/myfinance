// EZ-Fin · send-invite
// POST {login_id}  → emails an invite to a reserved (not yet signed up) Member login.
// Caller must be logged in and be the account Owner (or an EZ-Fin admin).
// Limit: one invite per login per day (email_log unique client + kind + date).
import { createClient } from "npm:@supabase/supabase-js@2";

const APP_URL = "https://ez-fin.co.za/";
const FROM = "EZ-Fin <noreply@ez-fin.co.za>";
const REPLY_TO = "admin@ez-fin.co.za";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });
const esc = (s: string) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const saToday = () => new Date().toLocaleDateString("en-CA", { timeZone: "Africa/Johannesburg" });

function inviteEmail(inviter: string, invitee: string, email: string) {
  const link = APP_URL + "?invite=" + encodeURIComponent(email);
  const subject = `${inviter} has invited you to EZ-Fin`;
  const body = `<p>Hi ${esc(invitee || "there")},</p>
<p><b>${esc(inviter)}</b> has added you to their EZ-Fin account, so you can manage your household finances together.</p>
<p>To join, click the button below and create your login. Your email address <b>${esc(email)}</b> is filled in for you — please keep it exactly as it is, otherwise you will not be linked to ${esc(inviter)}'s account.</p>
<p>There is nothing to pay — the account owner looks after the subscription.</p>`;
  const html = `<!doctype html><html><body style="margin:0;background:#eaf5fc;font-family:Segoe UI,Roboto,Arial,sans-serif;color:#1b2a3d">
<span style="display:none;max-height:0;overflow:hidden">${esc(inviter)} added you to their EZ-Fin account</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eaf5fc;padding:24px 12px"><tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#ffffff;border:1px solid #cfe3f1;border-radius:14px">
<tr><td style="padding:22px 26px 6px"><div style="font-size:22px;font-weight:800;color:#0b2e63">EZ-Fin</div>
<div style="font-size:12px;color:#5a6b80">Organize Today – Thrive Tomorrow</div></td></tr>
<tr><td style="padding:10px 26px 4px"><h1 style="font-size:19px;color:#0b2e63;margin:8px 0 12px">${esc(subject)}</h1>
<div style="font-size:15px;line-height:1.6">${body}</div>
<p style="margin:22px 0"><a href="${link}" style="background:#175b9e;color:#ffffff;text-decoration:none;font-weight:700;padding:12px 22px;border-radius:10px;display:inline-block">Accept invite &amp; sign up</a></p>
<p style="font-size:13px;color:#5a6b80">Not expecting this? You can ignore this email. Questions? Write to <a href="mailto:${REPLY_TO}" style="color:#175b9e">${REPLY_TO}</a>.</p></td></tr>
<tr><td style="padding:14px 26px 20px;border-top:1px solid #cfe3f1;font-size:11.5px;color:#7a8a9c">
You are receiving this email because an EZ-Fin account owner added your email address. EZ-Fin · 33 Beach Road, Westbrook, Tongaat, 4439 · <a href="${APP_URL}privacy.html" style="color:#7a8a9c">Privacy Policy</a></td></tr>
</table></td></tr></table></body></html>`;
  const text = `Hi ${invitee || "there"},\n\n${inviter} has added you to their EZ-Fin account.\nTo join, open this link and sign up with ${email} (keep the email exactly the same):\n${link}\n\nNot expecting this? Ignore this email.\nEZ-Fin · ${REPLY_TO}`;
  return { subject, html, text };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });

  // who is calling?
  const jwt = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!jwt) return json({ error: "Please log in again." }, 401);
  const { data: u, error: uErr } = await admin.auth.getUser(jwt);
  if (uErr || !u?.user) return json({ error: "Please log in again." }, 401);

  let body: any = {}; try { body = await req.json(); } catch { /* empty */ }
  const loginId = String(body.login_id || "");
  if (!/^[0-9a-f-]{36}$/i.test(loginId)) return json({ error: "Missing login." }, 400);

  const { data: target } = await admin.from("client_logins")
    .select("id,client_id,email,full_name,role,status,user_id").eq("id", loginId).maybeSingle();
  if (!target) return json({ error: "That user was not found." }, 404);

  // caller must be the Owner of the same account, or an EZ-Fin admin
  const { data: me } = await admin.from("client_logins")
    .select("client_id,role,status,full_name").eq("user_id", u.user.id).maybeSingle();
  const { data: isAdmin } = await admin.from("admins").select("user_id").eq("user_id", u.user.id).maybeSingle();
  const isOwner = me && me.role === "Owner" && me.status === "Active" && me.client_id === target.client_id;
  if (!isOwner && !isAdmin) return json({ error: "Only the account owner can send invites." }, 403);

  if (target.role !== "Member") return json({ error: "Invites are only for added users." }, 400);
  if (target.user_id) return json({ error: "This person has already joined." }, 400);
  if (target.status !== "Active") return json({ error: "This user is disabled. Enable them first." }, 400);

  // who is inviting? (owner's name)
  let inviter = "";
  if (isOwner) inviter = me!.full_name || "";
  if (!inviter) {
    const { data: o } = await admin.from("client_logins").select("full_name").eq("client_id", target.client_id).eq("role", "Owner").maybeSingle();
    const { data: c } = await admin.from("clients").select("first_name,last_name").eq("id", target.client_id).maybeSingle();
    inviter = o?.full_name || [c?.first_name, c?.last_name].filter(Boolean).join(" ") || "An EZ-Fin user";
  }
  const invitee = String(target.full_name || "").split(" ")[0];

  if (!Deno.env.get("RESEND_API_KEY")) return json({ error: "Email is not set up yet." }, 500);

  // claim today's slot first (one invite per login per day)
  const kind = "invite_" + target.id;
  const { data: claimed, error: cErr } = await admin.from("email_log")
    .insert({ client_id: target.client_id, email: target.email, kind, ref_date: saToday(), status: "Sent" }).select("id").maybeSingle();
  if (cErr || !claimed) return json({ error: "An invite was already sent to this person today. Please try again tomorrow." }, 429);

  try {
    const m = inviteEmail(inviter, invitee, target.email);
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${Deno.env.get("RESEND_API_KEY")}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: FROM, to: [target.email], reply_to: REPLY_TO, subject: m.subject, html: m.html, text: m.text }),
    });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(d?.message || d?.error || `Resend HTTP ${res.status}`);
    await admin.from("email_log").update({ provider_id: String(d?.id || "") }).eq("id", claimed.id);
    return json({ sent: true, to: target.email });
  } catch (e) {
    const msg = (e as Error).message || "Send failed";
    // free the slot so the owner can retry straight away, but keep a record of the failure
    await admin.from("email_log").update({ status: "Failed", error: msg.slice(0, 300), kind: kind + "_failed_" + Date.now() }).eq("id", claimed.id);
    console.error("send-invite failed", msg);
    return json({ error: "The invite email could not be sent. Please try again." }, 502);
  }
});
