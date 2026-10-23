-- =======================================================
-- CyberGuard Grid MySQL Database Initialization Schema
-- =======================================================

CREATE DATABASE IF NOT EXISTS cyberguard_grid;
USE cyberguard_grid;

-- 1. Vulnerabilities Table
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id VARCHAR(64) PRIMARY KEY,
  cve_id VARCHAR(64) NOT NULL,
  title VARCHAR(512) NOT NULL,
  description TEXT NOT NULL,
  severity VARCHAR(32) NOT NULL,
  cvss_score DECIMAL(4,1) NOT NULL,
  cvss_vector VARCHAR(255),
  attack_vector VARCHAR(64),
  attack_complexity VARCHAR(64),
  privileges_required VARCHAR(64),
  user_interaction VARCHAR(64),
  affected_vendor VARCHAR(255) NOT NULL,
  affected_product VARCHAR(255) NOT NULL,
  affected_versions TEXT,
  published_date VARCHAR(64) NOT NULL,
  modified_date VARCHAR(64) NOT NULL,
  exploit_available TINYINT(1) NOT NULL DEFAULT 0,
  known_exploited TINYINT(1) NOT NULL DEFAULT 0,
  source VARCHAR(255) NOT NULL,
  references_json TEXT,
  `references` TEXT,
  remediation TEXT,
  last_updated VARCHAR(64) NOT NULL,
  cyberguard_priority VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
  cyberguard_score INT NOT NULL DEFAULT 50,
  confidence INT NOT NULL DEFAULT 80,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT uq_vuln_cve UNIQUE (cve_id),
  INDEX idx_vuln_cve (cve_id),
  INDEX idx_vuln_severity (severity),
  INDEX idx_vuln_cvss (cvss_score),
  INDEX idx_vuln_published (published_date),
  INDEX idx_vuln_vendor (affected_vendor),
  INDEX idx_vuln_product (affected_product),
  INDEX idx_vuln_known_exploited (known_exploited)
);

-- 2. Vulnerability Sources Table
CREATE TABLE IF NOT EXISTS vulnerability_sources (
  id VARCHAR(64) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  type VARCHAR(64) NOT NULL,
  url VARCHAR(512) NOT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  last_sync_at VARCHAR(64),
  sync_status VARCHAR(32) NOT NULL DEFAULT 'IDLE',
  error_message TEXT,
  records_count INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Sync Logs Table
CREATE TABLE IF NOT EXISTS sync_logs (
  id VARCHAR(64) PRIMARY KEY,
  source_name VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL,
  records_added INT NOT NULL DEFAULT 0,
  records_updated INT NOT NULL DEFAULT 0,
  records_skipped INT NOT NULL DEFAULT 0,
  error_count INT NOT NULL DEFAULT 0,
  error_details TEXT,
  duration_ms INT NOT NULL DEFAULT 0,
  created_at VARCHAR(64) NOT NULL
);

-- 4. Affected Products Table
CREATE TABLE IF NOT EXISTS affected_products (
  id VARCHAR(64) PRIMARY KEY,
  vulnerability_id VARCHAR(64) NOT NULL,
  cve_id VARCHAR(64) NOT NULL,
  vendor VARCHAR(255) NOT NULL,
  product VARCHAR(255) NOT NULL,
  versions TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_aff_cve (cve_id),
  INDEX idx_aff_vuln (vulnerability_id),
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);
