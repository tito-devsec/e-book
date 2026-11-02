// OTP delivery providers.
//
// whatsapp_cloud: Meta WhatsApp Business Cloud API. Requires an approved AUTHENTICATION
//   template with one body parameter (the code) and a copy-code URL button, as Meta requires
//   for authentication templates.
// console: development only; prints the code to the server log. Refused in production.
// memory: tests only; codes are kept in an in-process outbox.

export function createOtpDelivery(cfg, logger) {
  if (cfg.otpProvider === 'whatsapp_cloud') {
    for (const k of ['whatsappPhoneNumberId', 'whatsappAccessToken', 'whatsappOtpTemplate']) {
      if (!cfg[k]) throw new Error(`OTP_PROVIDER=whatsapp_cloud requires ${k.replace(/[A-Z]/g, (c) => '_' + c).toUpperCase()}`);
    }
    return {
      name: 'whatsapp_cloud',
      async send(phoneE164, code) {
        const url = `https://graph.facebook.com/${cfg.whatsappApiVersion}/${cfg.whatsappPhoneNumberId}/messages`;
        const res = await fetch(url, {
          method: 'POST',
          headers: { Authorization: `Bearer ${cfg.whatsappAccessToken}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            messaging_product: 'whatsapp',
            to: phoneE164.replace(/^\+/, ''),
            type: 'template',
            template: {
              name: cfg.whatsappOtpTemplate,
              language: { code: cfg.whatsappOtpTemplateLang },
              components: [
                { type: 'body', parameters: [{ type: 'text', text: code }] },
                { type: 'button', sub_type: 'url', index: '0', parameters: [{ type: 'text', text: code }] },
              ],
            },
          }),
          signal: AbortSignal.timeout(10000),
        });
        if (!res.ok) {
          const body = await res.text().catch(() => '');
          logger.error('whatsapp otp delivery failed', { status: res.status, body: body.slice(0, 500) });
          throw new Error('OTP delivery failed');
        }
        return 'SENT';
      },
    };
  }
  if (cfg.otpProvider === 'memory') {
    const outbox = [];
    return { name: 'memory', outbox, async send(phone, code) { outbox.push({ phone, code, at: Date.now() }); return 'SENT'; } };
  }
  if (cfg.otpProvider === 'console') {
    return {
      name: 'console',
      async send(phone, code) {
        // Development only. Written straight to stderr so the redacting logger does not hide it.
        process.stderr.write(`[dev otp] ${phone}: ${code}\n`);
        return 'SENT';
      },
    };
  }
  throw new Error(`Unknown OTP_PROVIDER ${cfg.otpProvider}`);
}
