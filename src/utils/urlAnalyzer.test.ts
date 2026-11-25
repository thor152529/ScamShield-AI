import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeUrlLexically,
  classifyRiskScore,
  extractLexicalFeatures,
  isThreatIntelDomain,
  sanitizeScanUrlInput,
  validateScanUrl,
} from './urlAnalyzer';
import { buildDemoBenchmarkHistory, computeDashboardStats } from './demoData';

test('validateScanUrl rejects empty, whitespace, single-label hosts, and non-HTTP(S) schemes', () => {
  assert.equal(validateScanUrl('').valid, false);
  assert.equal(validateScanUrl('   ').valid, false);
  assert.equal(validateScanUrl('javascript:alert(1)').valid, false);
  assert.equal(validateScanUrl('ftp://example.com/file').valid, false);
  assert.equal(validateScanUrl('invalidhost').valid, false);
  assert.equal(validateScanUrl('https://example.com/login test').valid, false);
  assert.equal(validateScanUrl('https://999.168.1.1/login').valid, false);
});

test('validateScanUrl accepts valid http/https URLs and prepends https:// when missing', () => {
  const res = validateScanUrl('https://example.com');
  assert.equal(res.valid, true);
  assert.equal(res.normalizedUrl, 'https://example.com/');

  const bareRes = validateScanUrl('example.com');
  assert.equal(bareRes.valid, true);
  assert.equal(bareRes.normalizedUrl, 'https://example.com/');

  const ipRes = validateScanUrl('http://192.168.1.1/login');
  assert.equal(ipRes.valid, true);
});

test('extractLexicalFeatures accurately extracts all 10 specification features', () => {
  const { features } = extractLexicalFeatures('http://secure-login-verify.sub.example.com/auth');
  assert.equal(features.has_https, false);
  assert.equal(features.has_ip_address, false);
  assert.equal(features.hyphen_count, 2);
  assert.equal(features.subdomain_count, 2);
  assert.equal(features.dot_count, 3);
  assert.ok(features.suspicious_keyword_count >= 3);
  assert.equal(features.has_punycode, false);
  assert.equal(features.is_shortener, false);
  assert.equal(features.url_length, 'http://secure-login-verify.sub.example.com/auth'.length);
});

test('classifyRiskScore respects provisional 0-39 / 40-69 / 70-100 thresholds', () => {
  assert.equal(classifyRiskScore(12).risk_level, 'LOW');
  assert.equal(classifyRiskScore(39).risk_level, 'LOW');
  assert.equal(classifyRiskScore(40).risk_level, 'SUSPICIOUS');
  assert.equal(classifyRiskScore(69).risk_level, 'SUSPICIOUS');
  assert.equal(classifyRiskScore(70).risk_level, 'HIGH');
  assert.equal(classifyRiskScore(95).risk_level, 'HIGH');
});

test('PDF test case 1: https://example.com scores LOW without claiming absolute safety', () => {
  const result = analyzeUrlLexically('https://example.com');
  assert.equal(result.risk_level, 'LOW');
  assert.equal(result.prediction, 'LEGITIMATE');
  assert.ok(result.risk_score <= 39);
  assert.ok(result.indicators.includes('HTTPS is enabled'));
  assert.match(result.recommendation, /verify/i);
});

test('PDF test case 2: http://192.168.1.1/login scores HIGH', () => {
  const result = analyzeUrlLexically('http://192.168.1.1/login');
  assert.equal(result.risk_level, 'HIGH');
  assert.ok(result.risk_score >= 70);
  assert.ok(result.indicators.some((i) => i.includes('IP-based hostname')));
  assert.ok(result.indicators.some((i) => i.includes('without HTTPS')));
});

test('PDF test case 3: http://secure-login-verify-example.com scores HIGH', () => {
  const result = analyzeUrlLexically('http://secure-login-verify-example.com');
  assert.equal(result.risk_level, 'HIGH');
  assert.ok(result.risk_score >= 70);
  assert.ok(result.indicators.some((i) => i.toLowerCase().includes('keyword')));
});

test('Shortener and Punycode URLs are flagged accurately', () => {
  const shortRes = analyzeUrlLexically('https://bit.ly/3xyz99');
  assert.ok(shortRes.features?.is_shortener);
  assert.equal(shortRes.risk_level, 'SUSPICIOUS');
  assert.ok(shortRes.indicators.some((i) => i.includes('shortener')));
  assert.equal(shortRes.ssl_analysis?.protocol, 'HTTPS');
  assert.equal(shortRes.domain_age_analysis?.hostname_type, 'URL Shortener');

  const punyRes = analyzeUrlLexically('https://xn--pypal-4ve.com/verify');
  assert.ok(punyRes.features?.has_punycode);
  assert.ok(punyRes.risk_score >= 40);
  assert.equal(punyRes.domain_age_analysis?.hostname_type, 'Punycode / IDN');
});

test('threat_breakdown outputs all 4 cards with accurate severities', () => {
  const safeRes = analyzeUrlLexically('https://example.com');
  assert.equal(safeRes.threat_breakdown?.length, 4);
  assert.ok(safeRes.threat_breakdown?.every((c) => c.severity === 'safe'));

  const shortRes = analyzeUrlLexically('https://bit.ly/3xyz99');
  const shortRedirect = shortRes.threat_breakdown?.find((c) => c.id === 'redirect_risk');
  assert.equal(shortRedirect?.severity, 'warning');

  const highRes = analyzeUrlLexically('http://secure-bank-login-example.com');
  const spoofing = highRes.threat_breakdown?.find((c) => c.id === 'domain_spoofing');
  const ssl = highRes.threat_breakdown?.find((c) => c.id === 'ssl_https');
  const keywords = highRes.threat_breakdown?.find((c) => c.id === 'suspicious_keywords');
  assert.equal(spoofing?.severity, 'danger');
  assert.equal(ssl?.severity, 'danger');
  assert.equal(keywords?.severity, 'danger');

  const redirectRes = analyzeUrlLexically('https://portal.example.com/auth?next=https://evil.example.net');
  const redirectCard = redirectRes.threat_breakdown?.find((c) => c.id === 'redirect_risk');
  assert.equal(redirectCard?.severity, 'warning');
});

test('buildDemoBenchmarkHistory pre-populates 9 realistic entries across all 3 risk tiers', () => {
  const entries = buildDemoBenchmarkHistory();
  assert.ok(entries.length >= 8 && entries.length <= 10);
  assert.equal(entries.length, 9);
  assert.ok(entries.some((e) => e.risk_level === 'LOW'));
  assert.ok(entries.some((e) => e.risk_level === 'SUSPICIOUS'));
  assert.ok(entries.some((e) => e.risk_level === 'HIGH'));
});

test('sanitizeScanUrlInput strips accidental Markdown link syntax, trims whitespace, and prepends https://', () => {
  assert.equal(
    sanitizeScanUrlInput('](https://testsafebrowsing.appspot.com/s/phishing.html)'),
    'https://testsafebrowsing.appspot.com/s/phishing.html'
  );
  assert.equal(
    sanitizeScanUrlInput('  ](testsafebrowsing.appspot.com/s/phishing.html)  '),
    'https://testsafebrowsing.appspot.com/s/phishing.html'
  );
  assert.equal(
    sanitizeScanUrlInput('[Verify Account](https://example.com/login)'),
    'https://example.com/login'
  );
  assert.equal(
    sanitizeScanUrlInput('  <https://example.com/path>;  '),
    'https://example.com/path'
  );
  assert.equal(
    sanitizeScanUrlInput('  secure-bank-login.example.com/auth  '),
    'https://secure-bank-login.example.com/auth'
  );

  const check = validateScanUrl('  ](testsafebrowsing.appspot.com/s/phishing.html)  ');
  assert.equal(check.valid, true);
  assert.equal(check.normalizedUrl, 'https://testsafebrowsing.appspot.com/s/phishing.html');
});

test('computeDashboardStats ensures Total Scans equals Threats Blocked + Suspicious + Legitimate', () => {
  const demo = buildDemoBenchmarkHistory();
  const stats = computeDashboardStats(demo);
  assert.equal(stats.total, demo.length);
  assert.equal(stats.threatsBlocked + stats.suspiciousCount + stats.lowCount, stats.total);
  assert.ok(stats.threatsBlocked > 0);
  assert.ok(stats.suspiciousCount > 0);
  assert.ok(stats.lowCount > 0);
});

test('Known threat-intelligence test domains and phishing/spoofing URLs score 90-100 High Risk', () => {
  assert.equal(isThreatIntelDomain('testsafebrowsing.appspot.com'), true);

  const safeBrowsingPhish = analyzeUrlLexically('https://testsafebrowsing.appspot.com/s/phishing.html');
  assert.equal(safeBrowsingPhish.risk_level, 'HIGH');
  assert.equal(safeBrowsingPhish.prediction, 'PHISHING');
  assert.ok(safeBrowsingPhish.risk_score >= 90 && safeBrowsingPhish.risk_score <= 100);
  const spoofingCard = safeBrowsingPhish.threat_breakdown?.find((c) => c.id === 'domain_spoofing');
  assert.equal(spoofingCard?.severity, 'danger');
  assert.equal(spoofingCard?.status_label, 'Threat-Intel Flagged Domain');

  const safeBrowsingMalware = analyzeUrlLexically('https://testsafebrowsing.appspot.com/s/malware.html');
  assert.equal(safeBrowsingMalware.risk_level, 'HIGH');
  assert.equal(safeBrowsingMalware.prediction, 'MALICIOUS');
  assert.ok(safeBrowsingMalware.risk_score >= 90 && safeBrowsingMalware.risk_score <= 100);

  const brandSpoof = analyzeUrlLexically('https://paypal-security-verify-account.com/login');
  assert.equal(brandSpoof.risk_level, 'HIGH');
  assert.ok(brandSpoof.risk_score >= 90 && brandSpoof.risk_score <= 100);

  const multiSignal = analyzeUrlLexically('http://secure-login-verify-example.com');
  assert.equal(multiSignal.risk_level, 'HIGH');
  assert.ok(multiSignal.risk_score >= 90 && multiSignal.risk_score <= 100);
});
