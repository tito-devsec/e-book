// Central configuration. Every value comes from the environment; nothing secret is hardcoded.
const env = process.env;

function required(name) {
  const v = env[name];
  if (!v) throw new Error(`Missing required environment variable ${name}`);
  return v;
}

function bool(v, dflt) {
  if (v === undefined || v === '') return dflt;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

function int(v, dflt) {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) ? n : dflt;
}

export function loadConfig() {
  const nodeEnv = env.NODE_ENV || 'development';
  const isProd = nodeEnv === 'production';
  const cfg = {
    nodeEnv,
    isProd,
    isTest: nodeEnv === 'test',
    port: int(env.PORT, 3000),
    // Extra local ports so each application can have its own port in development or on one
    // server (e.g. reader 3000, website 3001, admin 3002). Which app answers on which port is
    // decided by the *_BASE_URL values.
    publicPort: int(env.PUBLIC_PORT, 0),
    adminPort: int(env.ADMIN_PORT, 0),
    readerPort: int(env.READER_PORT, 0),
    databaseUrl: required('DATABASE_URL'),
    databaseSsl: bool(env.DATABASE_SSL, false),
    // Hosts. When set, each application is served only on its own host.
    publicBaseUrl: env.PUBLIC_BASE_URL || `http://localhost:${int(env.PORT, 3000)}`,
    adminBaseUrl: env.ADMIN_BASE_URL || '',
    readerBaseUrl: env.READER_BASE_URL || '',
    trustProxy: env.TRUST_PROXY || (isProd ? '1' : 'false'),
    cookieSecure: bool(env.COOKIE_SECURE, isProd),
    // Pepper mixed into token/OTP/IP hashes. Must be long and random.
    hashPepper: required('HASH_PEPPER'),
    // Key management
    kmsProvider: env.KMS_PROVIDER || 'local',
    localMasterKey: env.LOCAL_MASTER_KEY || '',
    awsKmsKeyId: env.AWS_KMS_KEY_ID || '',
    awsRegion: env.AWS_REGION || '',
    // Storage
    storageDriver: env.STORAGE_DRIVER || 'local',
    storageLocalDir: env.STORAGE_LOCAL_DIR || './var/storage',
    s3Bucket: env.S3_BUCKET || '',
    s3Endpoint: env.S3_ENDPOINT || '',
    s3ForcePathStyle: bool(env.S3_FORCE_PATH_STYLE, false),
    // Uploads
    maxBookUploadMb: int(env.MAX_BOOK_UPLOAD_MB, 100),
    maxCoverUploadMb: int(env.MAX_COVER_UPLOAD_MB, 5),
    clamavHost: env.CLAMAV_HOST || '',
    clamavPort: int(env.CLAMAV_PORT, 3310),
    requireMalwareScan: bool(env.REQUIRE_MALWARE_SCAN, false),
    pdftoppmPath: env.PDFTOPPM_PATH || 'pdftoppm',
    pdfRenderDpi: int(env.PDF_RENDER_DPI, 110),
    // OTP delivery
    otpProvider: env.OTP_PROVIDER || (isProd ? 'whatsapp_cloud' : 'console'),
    whatsappApiVersion: env.WHATSAPP_API_VERSION || 'v21.0',
    whatsappPhoneNumberId: env.WHATSAPP_PHONE_NUMBER_ID || '',
    whatsappAccessToken: env.WHATSAPP_ACCESS_TOKEN || '',
    whatsappOtpTemplate: env.WHATSAPP_OTP_TEMPLATE || '',
    whatsappOtpTemplateLang: env.WHATSAPP_OTP_TEMPLATE_LANG || 'en',
    // Admin
    adminSessionHours: int(env.ADMIN_SESSION_HOURS, 12),
    adminIdleMinutes: int(env.ADMIN_IDLE_MINUTES, 60),
    requireAdminMfa: bool(env.REQUIRE_ADMIN_MFA, false),
    logLevel: env.LOG_LEVEL || (isProd ? 'info' : 'debug'),
  };

  if (cfg.hashPepper.length < 32) throw new Error('HASH_PEPPER must be at least 32 characters');
  if (cfg.kmsProvider === 'local' && !/^[0-9a-f]{64}$/i.test(cfg.localMasterKey)) {
    throw new Error('LOCAL_MASTER_KEY must be 64 hex characters (32 bytes) when KMS_PROVIDER=local');
  }
  if (isProd && cfg.otpProvider === 'console') {
    throw new Error('OTP_PROVIDER=console is not allowed in production');
  }
  if (isProd && !cfg.cookieSecure) throw new Error('COOKIE_SECURE must be true in production');
  return cfg;
}
