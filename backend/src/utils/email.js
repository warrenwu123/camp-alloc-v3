// backend/src/utils/email.js
// Email sending via SendGrid HTTP API

export async function sendEmail(env, { to, subject, html }) {
  if (!env.SENDGRID_KEY) {
    // Dev mode — just log
    console.log(`[EMAIL DEV] To: ${to} | Subject: ${subject}`);
    return;
  }
  const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.SENDGRID_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: to }] }],
      from: { email: env.EMAIL_FROM || 'noreply@campalloc.com', name: 'CampAlloc' },
      subject,
      content: [{ type: 'text/html', value: html }],
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    console.error('SendGrid error:', res.status, body);
    throw new Error('Failed to send email');
  }
}

export function verificationEmail(name, verifyUrl) {
  return {
    subject: 'Verify your CampAlloc email',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto">
        <h2 style="color:#f0a500">CampAlloc — Email Verification</h2>
        <p>Hi ${name},</p>
        <p>Click the button below to verify your email address. This link expires in <strong>24 hours</strong>.</p>
        <a href="${verifyUrl}" style="display:inline-block;background:#f0a500;color:#000;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:bold;margin:16px 0">Verify Email</a>
        <p style="color:#888;font-size:12px">If you didn't register, you can ignore this email.</p>
      </div>`,
  };
}

export function passwordResetEmail(name, resetUrl) {
  return {
    subject: 'Reset your CampAlloc password',
    html: `
      <div style="font-family:sans-serif;max-width:480px;margin:auto">
        <h2 style="color:#f0a500">CampAlloc — Password Reset</h2>
        <p>Hi ${name},</p>
        <p>Click the button below to reset your password. This link expires in <strong>1 hour</strong>.</p>
        <a href="${resetUrl}" style="display:inline-block;background:#f0a500;color:#000;padding:12px 28px;border-radius:6px;text-decoration:none;font-weight:bold;margin:16px 0">Reset Password</a>
        <p style="color:#888;font-size:12px">If you didn't request this, you can ignore this email.</p>
      </div>`,
  };
}
