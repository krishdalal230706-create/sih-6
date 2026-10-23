import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createRateLimiter } from '../middleware/rateLimiter.js';
import { validateRequestBody } from '../middleware/validator.js';

describe('API Hardening: Rate Limiting & Input Validation', () => {
  it('enforces request count limits and returns HTTP 429 when exceeded', () => {
    const limiter = createRateLimiter({
      windowMs: 1000,
      max: 3,
      message: 'Rate limit test reached'
    });

    let statusCode: number | null = null;
    let jsonResponse: any = null;

    const mockReq = {
      headers: { 'x-test-rate-limit': '1' },
      socket: { remoteAddress: '192.168.1.100' }
    } as any;

    const mockRes = {
      setHeader: (_name: string, _val: any) => {},
      status: (code: number) => {
        statusCode = code;
        return {
          json: (body: any) => {
            jsonResponse = body;
          }
        };
      }
    } as any;

    let nextCount = 0;
    const mockNext = () => {
      nextCount++;
    };

    // First 3 requests should pass
    limiter(mockReq, mockRes, mockNext);
    limiter(mockReq, mockRes, mockNext);
    limiter(mockReq, mockRes, mockNext);
    assert.strictEqual(nextCount, 3, 'First 3 requests should succeed');
    assert.strictEqual(statusCode, null, 'No error status for allowed requests');

    // 4th request must be rate limited with 429
    limiter(mockReq, mockRes, mockNext);
    assert.strictEqual(statusCode, 429, 'Should return HTTP 429');
    assert.strictEqual(jsonResponse?.error, 'Too Many Requests');
    assert.strictEqual(nextCount, 3, 'Next should not be invoked on rate limited request');
  });

  it('validates required fields, schema types, and numerical bounds correctly', () => {
    const validator = validateRequestBody({
      orgId: { type: 'string', required: true, minLength: 2, maxLength: 20 },
      score: { type: 'number', required: true, min: 0, max: 100 },
      isConfirmed: { type: 'boolean', required: false }
    });

    // 1. Valid request payload
    let validStatus: number | null = null;
    let nextCalled = false;
    const validReq = { body: { orgId: 'org-1', score: 84, isConfirmed: true } } as any;
    const validRes = {
      status: (c: number) => {
        validStatus = c;
        return { json: () => {} };
      }
    } as any;

    validator(validReq, validRes, () => {
      nextCalled = true;
    });
    assert.strictEqual(nextCalled, true, 'Valid payload should call next()');
    assert.strictEqual(validStatus, null, 'Valid payload should not set status code');

    // 2. Missing required field
    let invalidStatus: number | null = null;
    let errorResponse: any = null;
    const missingReq = { body: { score: 84 } } as any;
    const invalidRes = {
      status: (c: number) => {
        invalidStatus = c;
        return {
          json: (body: any) => {
            errorResponse = body;
          }
        };
      }
    } as any;

    validator(missingReq, invalidRes, () => {});
    assert.strictEqual(invalidStatus, 400, 'Missing required field must yield HTTP 400');
    assert.ok(errorResponse?.details?.some((d: string) => d.includes('orgId')));

    // 3. Out-of-bounds number
    let outOfBoundsStatus: number | null = null;
    let outOfBoundsError: any = null;
    const outOfBoundsReq = { body: { orgId: 'org-1', score: 150 } } as any;
    const outOfBoundsRes = {
      status: (c: number) => {
        outOfBoundsStatus = c;
        return {
          json: (body: any) => {
            outOfBoundsError = body;
          }
        };
      }
    } as any;

    validator(outOfBoundsReq, outOfBoundsRes, () => {});
    assert.strictEqual(outOfBoundsStatus, 400, 'Score > 100 must yield HTTP 400');
    assert.ok(outOfBoundsError?.details?.some((d: string) => d.includes('cannot exceed 100')));
  });
});
