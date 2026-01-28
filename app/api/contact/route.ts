import { NextResponse } from "next/server";
import nodemailer from "nodemailer";
import { z } from "zod";

const formSchema = z.object({
  email: z.string().email().min(2).max(50),
  subject: z.string().min(2).max(50),
  message: z.string().min(2).max(500),
  honeypot: z.string().optional(),
  ts: z.string().optional(),
});

const ALLOWED_ORIGINS = new Set([
  "https://swajp.me",
  "https://www.swajp.me",
  "http://localhost:3000",
]);

const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const RATE_LIMIT_MAX = 5;
const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

const ABUSE_ALERT_WINDOW_MS = 60 * 60 * 1000;
const abuseAlertStore = new Map<string, { lastAlertAt: number }>();

function getClientIp(req: Request) {
  const forwardedFor = req.headers.get("x-forwarded-for");
  if (forwardedFor) {
    return forwardedFor.split(",")[0]?.trim() || "unknown";
  }
  return req.headers.get("x-real-ip") || "unknown";
}

function isRateLimited(ip: string) {
  const now = Date.now();
  const entry = rateLimitStore.get(ip);
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  if (entry.count >= RATE_LIMIT_MAX) {
    return true;
  }
  entry.count += 1;
  return false;
}

function escapeHtml(input: string) {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function isLikelySpam(message: string) {
  const urlMatches = message.match(/https?:\/\//gi) ?? [];
  return urlMatches.length > 2;
}

async function maybeAlertAbuse(ip: string, reason: string, req: Request) {
  const now = Date.now();
  const entry = abuseAlertStore.get(ip);
  if (entry && now - entry.lastAlertAt < ABUSE_ALERT_WINDOW_MS) {
    return;
  }
  abuseAlertStore.set(ip, { lastAlertAt: now });

  const ua = req.headers.get("user-agent") ?? "unknown";
  console.warn(`[contact] abuse ip=${ip} reason=${reason} ua=${ua}`);

  const alertTo = process.env.ALERT_EMAIL;
  if (!alertTo) return;

  const transporter = nodemailer.createTransport({
    host: "smtp.seznam.cz",
    port: 465,
    secure: true,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  });

  try {
    await transporter.sendMail({
      from: '"sender@swajp.me" <sender@swajp.me>',
      to: alertTo,
      subject: "Contact form abuse detected",
      html: `
        <h2>Abuse detected</h2>
        <ul>
          <li>IP: ${escapeHtml(ip)}</li>
          <li>Reason: ${escapeHtml(reason)}</li>
          <li>User-Agent: ${escapeHtml(ua)}</li>
        </ul>
      `,
    });
  } catch (error) {
    console.log(error);
  }
}

export async function POST(req: Request) {
  const origin = req.headers.get("origin");
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    await maybeAlertAbuse(getClientIp(req), "forbidden-origin", req);
    return NextResponse.json({ message: "Forbidden" }, { status: 403 });
  }

  const ip = getClientIp(req);
  if (isRateLimited(ip)) {
    await maybeAlertAbuse(ip, "rate-limited", req);
    return NextResponse.json(
      { message: "Too many requests" },
      { status: 429 }
    );
  }

  let values: z.infer<typeof formSchema>;
  try {
    values = formSchema.parse(await req.json());
  } catch {
    return NextResponse.json({ message: "Invalid payload" }, { status: 400 });
  }

  const { email, subject, message, honeypot, ts } = values;
  if (honeypot) {
    await maybeAlertAbuse(ip, "honeypot", req);
    return NextResponse.json({ message: "Form sent successfully" });
  }

  const submittedAt = ts ? Number(ts) : null;
  if (submittedAt && Date.now() - submittedAt < 3000) {
    await maybeAlertAbuse(ip, "too-fast", req);
    return NextResponse.json({ message: "Form sent successfully" });
  }

  if (isLikelySpam(message)) {
    await maybeAlertAbuse(ip, "link-spam", req);
    return NextResponse.json({ message: "Form sent successfully" });
  }

  const transporter = nodemailer.createTransport({
    host: "smtp.seznam.cz",
    port: 465,
    secure: true,
    auth: {
      user: process.env.NODEMAILER_USER,
      pass: process.env.NODEMAILER_PASS,
    },
  });

  try {
    await transporter.sendMail({
      from: '"sender@swajp.me" <sender@swajp.me>',
      to: "me@swajp.me",
      subject: `Contact: ${subject}`,
      replyTo: email,
      html: `
        <h2>Details</h2>
        <ul>
            <li>Email: ${escapeHtml(email)}</li>
        </ul>
        <h2>Message</h2>
      <p>${escapeHtml(message)}</p>
      `,
    });
    return NextResponse.json(
      { message: "Form sent successfully" },
      { status: 200 }
    );
  } catch (error) {
    console.log(error);
    return NextResponse.json(
      { message: "Error, try it again." },
      { status: 500 }
    );
  }
}
