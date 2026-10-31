import crypto from 'crypto';
import { isDemoMode } from '../config/authConfig.js';

interface CodeEntry {
  code: string;
  purpose: 'FORGOT_PASSWORD' | 'VERIFY_EMAIL';
  expiresAt: number;
}

interface ResetTokenEntry {
  token: string;
  expiresAt: number;
}

class EmailService {
  private codes = new Map<string, CodeEntry>();
  private resetTokens = new Map<string, ResetTokenEntry>();

  /**
   * Generates a 6-digit verification code valid for 10 minutes.
   */
  public generateCode(email: string, purpose: 'FORGOT_PASSWORD' | 'VERIFY_EMAIL'): string {
    const normalizedEmail = email.trim().toLowerCase();
    // 6-digit numeric code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    this.codes.set(`${normalizedEmail}:${purpose}`, {
      code,
      purpose,
      expiresAt
    });

    console.log(`📧 [EmailService] ${purpose} code for ${normalizedEmail}: [ ${code} ] (expires in 10m)`);
    return code;
  }

  /**
   * Verifies the 6-digit code.
   */
  public verifyCode(email: string, code: string, purpose: 'FORGOT_PASSWORD' | 'VERIFY_EMAIL'): boolean {
    const normalizedEmail = email.trim().toLowerCase();
    const key = `${normalizedEmail}:${purpose}`;
    const entry = this.codes.get(key);

    if (!entry) return false;
    if (Date.now() > entry.expiresAt) {
      this.codes.delete(key);
      return false;
    }

    if (entry.code === code.trim()) {
      this.codes.delete(key);
      return true;
    }

    return false;
  }

  /**
   * Creates a single-use password reset token valid for 15 minutes after code verification.
   */
  public createResetToken(email: string): string {
    const normalizedEmail = email.trim().toLowerCase();
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 15 * 60 * 1000;

    this.resetTokens.set(normalizedEmail, { token, expiresAt });
    return token;
  }

  /**
   * Validates a password reset token.
   */
  public verifyResetToken(email: string, token: string): boolean {
    const normalizedEmail = email.trim().toLowerCase();
    const entry = this.resetTokens.get(normalizedEmail);

    if (!entry) return false;
    if (Date.now() > entry.expiresAt) {
      this.resetTokens.delete(normalizedEmail);
      return false;
    }

    return entry.token === token;
  }

  /**
   * Invalidates password reset token after use.
   */
  public clearResetToken(email: string): void {
    const normalizedEmail = email.trim().toLowerCase();
    this.resetTokens.delete(normalizedEmail);
  }

  /**
   * Inspects if demo mode is enabled to conditionally expose simulated code on screen.
   */
  public isSimulatedDelivery(): boolean {
    return isDemoMode() || !process.env.SMTP_HOST;
  }
}

export const emailService = new EmailService();

