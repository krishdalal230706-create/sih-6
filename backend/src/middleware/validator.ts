import { Request, Response, NextFunction } from 'express';

export interface FieldValidationSchema {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  required?: boolean;
  min?: number;
  max?: number;
  minLength?: number;
  maxLength?: number;
  allowedValues?: any[];
}

export type ValidationSchema = Record<string, FieldValidationSchema>;

/**
 * Validates request bodies against a lightweight declarative schema.
 * Rejects invalid types, payload over-sizes, and malicious non-string types.
 */
export function validateRequestBody(schema: ValidationSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const body = req.body;

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Request body must be a valid JSON object.'
      });
    }

    const errors: string[] = [];

    for (const [field, rule] of Object.entries(schema)) {
      const val = body[field];

      if (rule.required && (val === undefined || val === null || val === '')) {
        errors.push(`Field '${field}' is required.`);
        continue;
      }

      if (val === undefined || val === null) {
        continue;
      }

      // Type checks
      if (rule.type === 'array') {
        if (!Array.isArray(val)) {
          errors.push(`Field '${field}' must be an array.`);
        }
      } else if (rule.type === 'string') {
        if (typeof val !== 'string') {
          errors.push(`Field '${field}' must be a string.`);
        } else {
          if (rule.minLength !== undefined && val.length < rule.minLength) {
            errors.push(`Field '${field}' length must be at least ${rule.minLength} characters.`);
          }
          if (rule.maxLength !== undefined && val.length > rule.maxLength) {
            errors.push(`Field '${field}' length cannot exceed ${rule.maxLength} characters.`);
          }
        }
      } else if (rule.type === 'number') {
        if (typeof val !== 'number' || isNaN(val)) {
          errors.push(`Field '${field}' must be a valid number.`);
        } else {
          if (rule.min !== undefined && val < rule.min) {
            errors.push(`Field '${field}' value must be at least ${rule.min}.`);
          }
          if (rule.max !== undefined && val > rule.max) {
            errors.push(`Field '${field}' value cannot exceed ${rule.max}.`);
          }
        }
      } else if (rule.type === 'boolean') {
        if (typeof val !== 'boolean') {
          errors.push(`Field '${field}' must be a boolean.`);
        }
      }

      // Allowed values enum check
      if (rule.allowedValues && !rule.allowedValues.includes(val)) {
        errors.push(`Field '${field}' must be one of: [${rule.allowedValues.join(', ')}].`);
      }
    }

    if (errors.length > 0) {
      return res.status(400).json({
        error: 'Validation Error',
        details: errors
      });
    }

    next();
  };
}
