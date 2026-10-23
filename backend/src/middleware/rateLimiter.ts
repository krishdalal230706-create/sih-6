import { Request, Response, NextFunction } from 'express';

interface RateLimitOptions {
  windowMs: number;
  max: number;
  message?: string;
  skipFailedRequests?: boolean;
}

interface ClientRecord {
  count: number;
  resetTime: number;
}

/**
 * Creates an in-memory sliding-window rate limiting middleware.
 * Zero external dependencies, suitable for local dev, demo mode, and cloud container deployments.
 */
export function createRateLimiter(options: RateLimitOptions) {
  const { windowMs, max, message = 'Too many requests, please try again later.' } = options;
  const clients = new Map<string, ClientRecord>();

  // Periodically clean up expired client entries every 5 minutes to prevent memory leaks
  const cleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, record] of clients.entries()) {
      if (now > record.resetTime) {
        clients.delete(key);
      }
    }
  }, 5 * 60 * 1000);

  // Unref interval so it does not prevent node process from exiting in tests
  if (cleanupInterval.unref) {
    cleanupInterval.unref();
  }

  return (req: Request, res: Response, next: NextFunction) => {
    // In test environment, skip or relax rate limits unless explicitly testing rate limits
    if (process.env.NODE_ENV === 'test' && !req.headers['x-test-rate-limit']) {
      return next();
    }

    // Identify client by X-Forwarded-For (proxy) or IP address
    const clientIp =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.socket.remoteAddress ||
      '127.0.0.1';

    const now = Date.now();
    let record = clients.get(clientIp);

    if (!record || now > record.resetTime) {
      record = {
        count: 1,
        resetTime: now + windowMs
      };
      clients.set(clientIp, record);
    } else {
      record.count += 1;
    }

    const remaining = Math.max(0, max - record.count);
    const resetSeconds = Math.ceil((record.resetTime - now) / 1000);

    res.setHeader('X-RateLimit-Limit', max);
    res.setHeader('X-RateLimit-Remaining', remaining);
    res.setHeader('X-RateLimit-Reset', resetSeconds);

    if (record.count > max) {
      res.setHeader('Retry-After', resetSeconds);
      return res.status(429).json({
        error: 'Too Many Requests',
        message,
        retryAfterSeconds: resetSeconds
      });
    }

    next();
  };
}

/** General API rate limiter: 250 requests per minute */
export const generalApiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 250,
  message: 'API rate limit exceeded. Please throttle your requests.'
});

/** Sensitive state-mutation limiter: 40 requests per minute */
export const strictMutationLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 40,
  message: 'Security protection: State modification rate limit exceeded. Please wait a minute.'
});
