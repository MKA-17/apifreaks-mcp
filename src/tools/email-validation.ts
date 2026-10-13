import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { ENDPOINTS } from "../endpoints.js";
import { callApi } from "../client.js";
import { READ_ONLY, type Body } from "../constants.js";

const EMAIL_DESC = "Email address to validate (e.g. 'user@example.com').";
const NAME_DESC = "Optional name or label for record tracking.";
const IP_DESC =
  "Optional IPv4 or IPv6 address for geolocation and security enrichment. " +
  "When set, the response may include 'ip' plus an 'address' object with location and security fields " +
  "(threat_score, Tor/proxy/bot/spam/cloud-provider flags).";

const EmailEntry = z.object({
  email: z.string().describe(EMAIL_DESC),
  name: z.string().optional().describe(NAME_DESC),
  ip: z.string().optional().describe(IP_DESC),
});

const NonBlankEmail = z.string().refine((value) => value.trim().length > 0, {
  message: "emails must not contain blank entries",
});

export function register(server: McpServer, apiKey: string): void {
  server.registerTool(
    "email_validate",
    {
      title: "Email Validation",
      description:
        "Validate one email address: syntax, domain DNS, disposable/spam/free/catch-all flags, " +
        "and whether it looks deliverable. " +
        "Read 'validEmail': 'valid' (deliverable; 'reason' omitted), " +
        "'accept_all' (catch-all domain accepted the recipient; mailbox unconfirmed — pairs with domain.catchAll=true), " +
        "'invalid' (rejected, or domain accepts no mail), 'INVALID_EMAIL' (syntax failure; treat as invalid), " +
        "'unknown' (inconclusive; common for no-MX domains probed via A record), " +
        "'risky' (mailbox full or greylisted), or 'app_server_blocked' (verifier IP blocked). " +
        "When not 'valid', 'reason' explains why. " +
        "'dns' may be absent. 'dns.mxRecord' lists every host at the lowest MX preference " +
        "(absent when there is no MX; ['.'] means null MX / accepts no mail). " +
        "'dns.aRecord' is present when there is no MX but an address record exists. " +
        "Optional: pass 'ip' to attach geolocation and threat signals for that IP.",
      inputSchema: EmailEntry,
      annotations: READ_ONLY,
    },
    async ({ email, name, ip }) => {
      const body: Body = { email };
      if (name !== undefined) body["name"] = name;
      if (ip !== undefined) body["ip"] = ip;
      const data = await callApi(
        ENDPOINTS.EMAIL_VALIDATION_SINGLE,
        apiKey,
        {},
        body,
        "POST",
      );
      return {
        content: [{ type: "text" as const, text: JSON.stringify(data) }],
      };
    },
  );

  server.registerTool(
    "email_bulk_validate",
    {
      title: "Bulk Email Validation",
      description:
        "Validate up to 100 email addresses in one request. Each address is checked independently, " +
        "so one failure does not drop the rest of the batch. " +
        "The response is 'emailResponse': an array of the same per-email result as 'email_validate'.",
      inputSchema: z.object({
        emails: z
          .array(EmailEntry)
          .max(100)
          .describe(
            'List of email objects (max 100). Each object must include "email"; "name" and "ip" are optional. Example: [{"email":"user@example.com"},{"email":"admin@example.org","ip":"8.8.8.8"}]',
          ),
      }),
      annotations: READ_ONLY,
    },
    async ({ emails }) => {
      const emailData = emails.map((entry) => {
        const item: Body = { email: entry.email };
        if (entry.name !== undefined) item["name"] = entry.name;
        if (entry.ip !== undefined) item["ip"] = entry.ip;
        return item;
      });
      const data = await callApi(
        ENDPOINTS.EMAIL_VALIDATION_BULK,
        apiKey,
        {},
        { emailData },
        "POST",
      );
      return {
        content: [{ type: "text" as const, text: JSON.stringify(data) }],
      };
    },
  );

  server.registerTool(
    "email_disposable_check",
    {
      title: "Disposable Email Checker",
      description:
        "Check whether one email address comes from a throwaway provider, whether its domain resolves " +
        "and has mail servers, and whether it is a free-provider, spam-listed, or role-based address. " +
        "A malformed address still returns a normal result: validSyntax is false, and domain contains only " +
        "name plus validDomain=false. account and dns are omitted when validSyntax is false. " +
        "domain.disposable is true for throwaway providers, domain.free for free providers, domain.spam when spam-listed, " +
        "and domain.validDomain when the domain resolves. account.role is true for a shared or role mailbox. " +
        "dns.mxRecord lists mail exchangers; dns.aRecord lists A records. Either DNS array may be absent.",
      inputSchema: z.object({
        email: z.string().describe(EMAIL_DESC),
      }),
      annotations: READ_ONLY,
    },
    async ({ email }) => {
      const data = await callApi(ENDPOINTS.EMAIL_DISPOSABLE, apiKey, {
        email,
      });
      return {
        content: [{ type: "text" as const, text: JSON.stringify(data) }],
      };
    },
  );

  server.registerTool(
    "email_bulk_disposable_check",
    {
      title: "Bulk Disposable Email Checker",
      description:
        "Run the same checks as 'email_disposable_check' against up to 100 email addresses in one request. " +
        "The response is 'disposableEmailResponse': one result per submitted address, in request order, " +
        "using the same schema as the single check. A malformed address never fails the batch " +
        "(validSyntax and domain.validDomain are false). A blank or whitespace-only entry rejects the whole request.",
      inputSchema: z.object({
        emails: z
          .array(NonBlankEmail)
          .min(1)
          .max(100)
          .describe(
            'Email addresses to check (max 100). Blank or whitespace-only entries are rejected. Example: ["john@microsoft.com","test@mailinator.com"]',
          ),
      }),
      annotations: READ_ONLY,
    },
    async ({ emails }) => {
      const data = await callApi(
        ENDPOINTS.EMAIL_DISPOSABLE_BULK,
        apiKey,
        {},
        { emails },
        "POST",
      );
      return {
        content: [{ type: "text" as const, text: JSON.stringify(data) }],
      };
    },
  );
}
