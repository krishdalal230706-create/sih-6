import dotenv from 'dotenv';
dotenv.config();

const isProduction = process.env.NODE_ENV === 'production';
const isDemo = process.env.DEMO_MODE === 'true' || (!isProduction && process.env.DEMO_MODE !== 'false');
const enableEndpointAgent = process.env.ENABLE_ENDPOINT_AGENT === 'true';

let jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  if (isDemo) {
    console.warn('⚠️ [SECURITY WARNING] DEMO_MODE active: Using fallback JWT_SECRET. In production, configure a 32+ character JWT_SECRET in environment variables.');
    jwtSecret = 'cyberguard_prototype_jwt_secret_key_change_in_production_min32chars';
  } else {
    console.error('❌ [FATAL SECURITY ERROR] JWT_SECRET environment variable is missing when DEMO_MODE is not true. Aborting server start.');
    process.exit(1);
  }
}

let commandSigningSecret = process.env.COMMAND_SIGNING_SECRET;
if (!commandSigningSecret) {
  if (isDemo) {
    commandSigningSecret = 'cyberguard_prototype_command_hmac_secret_min32chars';
  } else {
    console.error('❌ [FATAL SECURITY ERROR] COMMAND_SIGNING_SECRET environment variable is missing in production mode. Aborting server start.');
    process.exit(1);
  }
}

export const AUTH_CONFIG = {
  JWT_SECRET: jwtSecret,
  COMMAND_SIGNING_SECRET: commandSigningSecret,
  JWT_EXPIRES_IN: '24h',
  SALT_ROUNDS: 10,
  IS_DEMO: isDemo,
  ENABLE_ENDPOINT_AGENT: enableEndpointAgent
};

export function isDemoMode(): boolean {
  return AUTH_CONFIG.IS_DEMO;
}

