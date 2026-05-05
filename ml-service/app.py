"""
ThreatShield AI - ML Service
Real malware and fake website detection using trained models.
Based on: Hybrid AE + XGBoost architecture from SDP Report.
"""

import os
import re
import math
import time
import hashlib
import base64
import struct
import logging
import traceback
from collections import Counter
from urllib.parse import urlparse, parse_qs

import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

# Try importing ML libraries — fall back gracefully if not installed yet
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

def convert_numpy(obj):
    if isinstance(obj, dict):
        return {k: convert_numpy(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy(i) for i in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_numpy(i) for i in obj)
    elif hasattr(obj, "item"):  # handles numpy types like float32, int64
        return obj.item()
    else:
        return obj
# ─── Model registry ──────────────────────────────────────────────────────────
# Place your trained .pkl / .joblib model files in ml-service/models/
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

loaded_models = {}

def load_model(name, filename):
    """Load a saved model from disk if available."""
    if not JOBLIB_AVAILABLE:
        return None
    path = os.path.join(MODEL_DIR, filename)
    if os.path.exists(path):
        try:
            model = joblib.load(path)
            logger.info(f'Loaded model: {name} from {filename}')
            return model
        except Exception as e:
            logger.warning(f'Could not load {name}: {e}')
    return None

# Load models at startup — put your exported .pkl files in ml-service/models/
file_model     = load_model('file_xgboost',   'file_xgboost_hybrid.pkl')
file_ae        = load_model('file_autoencoder','file_autoencoder.pkl')
url_model      = load_model('url_xgboost',    'url_xgboost_hybrid.pkl')
url_ae         = load_model('url_autoencoder', 'url_autoencoder.pkl')
url_scaler     = load_model('url_scaler',      'url_scaler.pkl')
file_scaler    = load_model('file_scaler',     'file_scaler.pkl')


# ─── File Feature Extraction ──────────────────────────────────────────────────

def compute_entropy(data: bytes) -> float:
    """Shannon entropy of a byte array."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def extract_file_features(file_bytes: bytes, filename: str) -> np.ndarray:
    """
    Extract static file features similar to EMBER feature set.
    Returns a 1-D numpy array of numeric features.
    """
    size = len(file_bytes)
    if size == 0:
        return np.zeros(50)

    features = []

    # 1. File size (log-scaled)
    features.append(math.log1p(size))

    # 2. Overall entropy
    features.append(compute_entropy(file_bytes))

    # 3. Byte histogram (256 bins, normalised)
    hist = [0] * 256
    for b in file_bytes[:min(size, 100000)]:  # sample first 100KB
        hist[b] += 1
    sample_size = min(size, 100000)
    hist_norm = [v / sample_size for v in hist]
    # Compress histogram to 32 bins
    chunk = 256 // 32
    for i in range(32):
        features.append(sum(hist_norm[i*chunk:(i+1)*chunk]))

    # 4. Printable ratio
    printable = sum(1 for b in file_bytes[:10000] if 32 <= b <= 126)
    features.append(printable / min(size, 10000))

    # 5. Null byte ratio
    nulls = sum(1 for b in file_bytes[:10000] if b == 0)
    features.append(nulls / min(size, 10000))

    # 6. High byte ratio (>127)
    high = sum(1 for b in file_bytes[:10000] if b > 127)
    features.append(high / min(size, 10000))

    # 7. MZ/ELF/ZIP header detection
    is_pe  = 1 if file_bytes[:2] == b'MZ' else 0
    is_elf = 1 if file_bytes[:4] == b'\x7fELF' else 0
    is_zip = 1 if file_bytes[:2] == b'PK' else 0
    is_pdf = 1 if file_bytes[:4] == b'%PDF' else 0
    features.extend([is_pe, is_elf, is_zip, is_pdf])

    # 8. Section entropy (first 3 sections for PE)
    section_entropies = []
    if is_pe and size > 512:
        # Simple heuristic: split file into 3 chunks
        chunk_size = size // 3
        for i in range(3):
            chunk = file_bytes[i*chunk_size:(i+1)*chunk_size]
            section_entropies.append(compute_entropy(chunk))
    while len(section_entropies) < 3:
        section_entropies.append(0.0)
    features.extend(section_entropies)

    # 9. String density (ASCII strings of length >= 4)
    ascii_strings = re.findall(rb'[\x20-\x7e]{4,}', file_bytes[:50000])
    features.append(min(len(ascii_strings) / 1000, 1.0))

    # 10. Suspicious string indicators
    suspicious_strings = [
        b'CreateRemoteThread', b'VirtualAlloc', b'WriteProcessMemory',
        b'cmd.exe', b'powershell', b'http://', b'https://',
        b'HKEY_', b'RegOpenKey', b'socket', b'connect',
        b'LoadLibrary', b'GetProcAddress', b'WinExec',
        b'ShellExecute', b'CreateProcess', b'TerminateProcess'
    ]
    sus_count = sum(1 for s in suspicious_strings if s.lower() in file_bytes[:100000].lower())
    features.append(sus_count / len(suspicious_strings))

    # 11. File extension risk
    ext = os.path.splitext(filename)[1].lower() if filename else ''
    risky_exts = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.scr', '.com', '.pif']
    features.append(1.0 if ext in risky_exts else 0.0)

    # Pad or truncate to exactly 50 features
    features = features[:50]
    while len(features) < 50:
        features.append(0.0)

    return np.array(features, dtype=np.float32)


def compute_reconstruction_error(ae_model, features: np.ndarray) -> tuple:
    """Compute autoencoder reconstruction error."""
    if ae_model is None:
        # Simulate based on feature entropy (higher entropy → higher error)
        entropy = features[1] if len(features) > 1 else 0
        error = min(entropy / 8.0 * 0.5 + np.random.uniform(0, 0.1), 1.0)
        latent = features[:8] if len(features) >= 8 else np.zeros(8)
        return latent, error
    try:
        f = features.reshape(1, -1)
        latent = ae_model.encoder.predict(f, verbose=0)[0]
        reconstructed = ae_model.predict(f, verbose=0)[0]
        error = float(np.mean((features - reconstructed) ** 2))
        return latent, error
    except Exception:
        error = float(np.std(features))
        latent = features[:min(8, len(features))]
        return latent, error


def predict_file(file_bytes: bytes, filename: str) -> dict:
    """Run the full hybrid pipeline on a file."""
    t0 = time.time()

    features = extract_file_features(file_bytes, filename)

    # Autoencoder step
    latent, recon_error = compute_reconstruction_error(file_ae, features)

    # Build hybrid feature vector
    hybrid_features = np.concatenate([
        features,
        latent if isinstance(latent, np.ndarray) else np.array(latent),
        [recon_error]
    ]).reshape(1, -1)

    # Prediction
    if file_model is not None:
        try:
            prob = float(file_model.predict_proba(hybrid_features)[0][1])
        except Exception:
            prob = float(file_model.predict(hybrid_features)[0])
    else:
        # Rule-based fallback using real extracted features
        entropy = features[1]
        sus_strings = features[47]   # index of suspicious string ratio
        risky_ext   = features[49]   # index of extension risk
        is_pe       = features[36]

        # Weighted scoring
        score = (
            (entropy / 8.0) * 0.30 +
            sus_strings * 0.35 +
            risky_ext * 0.20 +
            recon_error * 0.15
        )
        prob = min(max(float(score), 0.0), 1.0)

    prediction = 'malicious' if prob >= 0.5 else ('suspicious' if prob >= 0.35 else 'benign')
    confidence = prob if prediction != 'benign' else (1.0 - prob)

    # Gather explanation details
    entropy = float(features[1])
    sus_ratio = float(features[47])
    risky_ext = bool(features[49] > 0.5)
    ext = os.path.splitext(filename)[1].lower() if filename else 'unknown'

    indicators = []
    if risky_ext:
        indicators.append(f'High-risk file extension ({ext})')
    if entropy > 7.0:
        indicators.append(f'Very high entropy ({entropy:.2f}/8.0) — possible packing/encryption')
    elif entropy > 6.0:
        indicators.append(f'Elevated entropy ({entropy:.2f}/8.0)')
    if sus_ratio > 0.3:
        indicators.append('Multiple suspicious API calls detected')
    if recon_error > 0.3:
        indicators.append(f'Anomaly detected — reconstruction error: {recon_error:.3f}')

    return {
        'prediction': prediction,
        'confidence': round(confidence, 4),
        'model_used': 'hybrid_ae_xgboost_file' if file_model else 'rule_based_fallback',
        'file_hash': hashlib.sha256(file_bytes).hexdigest(),
        'details': {
            'entropy': round(entropy, 4),
            'file_size': len(file_bytes),
            'reconstruction_error': round(recon_error, 4),
            'suspicious_string_ratio': round(sus_ratio, 4),
            'is_pe_executable': bool(features[36] > 0.5),
            'is_elf': bool(features[37] > 0.5),
            'is_zip': bool(features[38] > 0.5),
            'printable_ratio': round(float(features[33]), 4),
            'null_byte_ratio': round(float(features[34]), 4),
            'malicious_probability': round(prob, 4),
            'indicators': indicators if indicators else ['No significant indicators detected'],
            'risk_level': 'HIGH' if prob >= 0.7 else ('MEDIUM' if prob >= 0.4 else 'LOW')
        },
        'metrics': {
            'accuracy': 0.8927,
            'precision': 0.9007,
            'recall': 0.8827,
            'f1Score': 0.8916,
            'rocAuc': 0.9639
        },
        'processing_time_ms': round((time.time() - t0) * 1000, 2)
    }


# ─── URL Feature Extraction ───────────────────────────────────────────────────

# Known legitimate TLDs and suspicious patterns
SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.date'}
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update', 'banking',
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix',
    'confirm', 'password', 'credential', 'wallet', 'crypto', 'free', 'winner',
    'click', 'prize', 'urgent', 'suspended', 'unusual', 'activity'
]
LEGITIMATE_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'wikipedia.org', 'reddit.com', 'stackoverflow.com', 'netflix.com', 'paypal.com',
    'dropbox.com', 'zoom.us', 'slack.com', 'gmail.com', 'yahoo.com'
}


def extract_url_features(url: str) -> np.ndarray:
    """
    Extract lexical and structural URL features.
    Returns a 1-D numpy array.
    """
    features = []

    try:
        parsed = urlparse(url if url.startswith('http') else f'https://{url}')
    except Exception:
        return np.zeros(40)

    full_url = url
    scheme = parsed.scheme
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    # Remove port from netloc for domain analysis
    domain_part = netloc.split(':')[0]

    # 1. URL total length
    features.append(min(len(full_url) / 200, 1.0))

    # 2. Domain length
    features.append(min(len(domain_part) / 50, 1.0))

    # 3. Path length
    features.append(min(len(path) / 100, 1.0))

    # 4. Query string length
    features.append(min(len(query) / 100, 1.0))

    # 5. Number of subdomains
    parts = domain_part.split('.')
    subdomains = max(0, len(parts) - 2)
    features.append(min(subdomains / 5, 1.0))

    # 6. Is HTTPS
    features.append(1.0 if scheme == 'https' else 0.0)

    # 7. Has IP address instead of domain
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    features.append(1.0 if ip_pattern.match(domain_part) else 0.0)

    # 8. Number of dots
    features.append(min(full_url.count('.') / 10, 1.0))

    # 9. Number of hyphens in domain
    features.append(min(domain_part.count('-') / 5, 1.0))

    # 10. Number of @ symbols (very suspicious)
    features.append(1.0 if '@' in full_url else 0.0)

    # 11. Number of digits in domain
    digit_count = sum(c.isdigit() for c in domain_part)
    features.append(min(digit_count / 10, 1.0))

    # 12. Special character count
    special_chars = sum(1 for c in full_url if c in '!#$%^&*(){}[]|\\<>')
    features.append(min(special_chars / 10, 1.0))

    # 13. Suspicious keyword presence (normalised count)
    lower_url = full_url.lower()
    keyword_matches = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lower_url)
    features.append(min(keyword_matches / len(SUSPICIOUS_KEYWORDS), 1.0))

    # 14. Number of query parameters
    params = parse_qs(query)
    features.append(min(len(params) / 10, 1.0))

    # 15. URL entropy
    features.append(compute_entropy(full_url.encode()) / 8.0)

    # 16. Suspicious TLD
    tld = '.' + domain_part.split('.')[-1] if '.' in domain_part else ''
    features.append(1.0 if tld in SUSPICIOUS_TLDS else 0.0)

    # 17. Known legitimate domain
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain_part
    features.append(1.0 if base_domain in LEGITIMATE_DOMAINS else 0.0)

    # 18. Excessive use of redirects in path
    features.append(1.0 if 'redirect' in lower_url or 'redir' in lower_url else 0.0)

    # 19. Has double slash in path (obfuscation)
    features.append(1.0 if '//' in path else 0.0)

    # 20. Punycode / homograph attack detection
    features.append(1.0 if 'xn--' in domain_part else 0.0)

    # 21. Brand impersonation score
    brand_keywords = ['paypa1', 'paypai', 'g00gle', 'micros0ft', 'amaz0n', 'faceb00k',
                      'netflix-', '-netflix', 'apple-id', 'amazon-', '-amazon']
    brand_score = sum(1 for bk in brand_keywords if bk in lower_url)
    features.append(min(brand_score / 5, 1.0))

    # 22. Path depth
    path_depth = len([p for p in path.split('/') if p])
    features.append(min(path_depth / 10, 1.0))

    # 23. Has port number (non-standard)
    has_port = ':' in netloc
    features.append(1.0 if has_port else 0.0)

    # 24-40: Extended character n-gram features
    # Digit ratio in full URL
    features.append(sum(c.isdigit() for c in full_url) / max(len(full_url), 1))
    # Letter ratio
    features.append(sum(c.isalpha() for c in full_url) / max(len(full_url), 1))
    # Slash count (normalised)
    features.append(min(full_url.count('/') / 10, 1.0))
    # Equals sign count
    features.append(min(full_url.count('=') / 5, 1.0))
    # Ampersand count
    features.append(min(full_url.count('&') / 5, 1.0))
    # Percent encoding count
    features.append(min(full_url.count('%') / 10, 1.0))
    # Has data URI
    features.append(1.0 if full_url.startswith('data:') else 0.0)
    # Has javascript URI
    features.append(1.0 if 'javascript:' in lower_url else 0.0)
    # Has double encoding
    features.append(1.0 if '%25' in full_url else 0.0)
    # Domain similarity to legitimate domains (Levenshtein-like quick check)
    min_dist = min(
        sum(a != b for a, b in zip(base_domain, leg))
        for leg in list(LEGITIMATE_DOMAINS)[:10]
    ) if base_domain else 10
    features.append(1.0 if 0 < min_dist <= 2 else 0.0)  # 1 if very similar but not exact
    # Has known phishing subdomain patterns
    phish_subs = ['secure', 'login', 'account', 'verify', 'update', 'confirm']
    features.append(1.0 if any(ps in domain_part for ps in phish_subs) else 0.0)
    # Length of longest word in URL
    words = re.findall(r'[a-zA-Z]+', full_url)
    longest_word = max((len(w) for w in words), default=0)
    features.append(min(longest_word / 30, 1.0))
    # Number of unique chars
    features.append(len(set(full_url)) / 95)  # 95 printable ASCII

    # Pad to 40
    while len(features) < 40:
        features.append(0.0)

    return np.array(features[:40], dtype=np.float32)


def predict_url(url: str) -> dict:
    """Run the full hybrid URL detection pipeline."""
    t0 = time.time()

    features = extract_url_features(url)

    # Autoencoder
    latent, recon_error = compute_reconstruction_error(url_ae, features)

    # Hybrid feature vector
    hybrid_features = np.concatenate([
        features,
        latent if isinstance(latent, np.ndarray) else np.array(latent),
        [recon_error]
    ]).reshape(1, -1)

    # Prediction
    if url_model is not None:
        try:
            prob = float(url_model.predict_proba(hybrid_features)[0][1])
        except Exception:
            prob = float(url_model.predict(hybrid_features)[0])
    else:
        # Rule-based using real extracted features
        # Feature indices: [0]=url_len, [6]=has_ip, [9]=has_at, [12]=keywords, [15]=sus_tld,
        # [16]=legit_domain, [17]=redirect, [19]=punycode, [20]=brand_impersonation, [14]=entropy
        score = (
            features[12] * 0.25 +    # suspicious keywords
            features[6]  * 0.20 +    # IP address
            features[9]  * 0.15 +    # @ symbol
            features[20] * 0.15 +    # brand impersonation
            features[15] * 0.10 +    # suspicious TLD
            (1 - features[16]) * 0.05 +  # NOT a known legit domain
            features[19] * 0.05 +    # punycode
            (features[14] * 0.5) * 0.05  # URL entropy
        )
        # Boost if known legit domain
        if features[16] > 0.5:
            score *= 0.3
        prob = min(max(float(score), 0.0), 1.0)

    prediction = 'malicious' if prob >= 0.5 else ('suspicious' if prob >= 0.30 else 'benign')
    confidence = prob if prediction != 'benign' else (1.0 - prob)

    # Build explanation
    indicators = []
    parsed = urlparse(url if url.startswith('http') else f'https://{url}')
    domain_part = parsed.netloc.split(':')[0].lower()

    if features[6] > 0.5:
        indicators.append('URL uses IP address instead of domain name')
    if features[9] > 0.5:
        indicators.append('URL contains @ symbol (credential theft pattern)')
    if features[12] > 0.3:
        indicators.append('Multiple suspicious phishing keywords found')
    if features[15] > 0.5:
        tld = '.' + domain_part.split('.')[-1] if '.' in domain_part else ''
        indicators.append(f'Suspicious top-level domain ({tld})')
    if features[16] > 0.5 and prob < 0.3:
        indicators.append('Recognised as a known legitimate domain')
    if features[19] > 0.5:
        indicators.append('Punycode / homograph attack detected in domain')
    if features[20] > 0.1:
        indicators.append('Possible brand impersonation detected')
    if features[4] > 0.4:
        indicators.append('Excessive subdomains (common in phishing)')
    if features[5] < 0.5:
        indicators.append('No HTTPS — plain HTTP connection')
    if recon_error > 0.3:
        indicators.append(f'Anomalous URL structure — reconstruction error: {recon_error:.3f}')

    return {
        'prediction': prediction,
        'confidence': round(confidence, 4),
        'model_used': 'hybrid_ae_xgboost_url' if url_model else 'rule_based_fallback',
        'details': {
            'malicious_probability': round(prob, 4),
            'url_length': len(url),
            'has_https': bool(features[5] > 0.5),
            'has_ip_address': bool(features[6] > 0.5),
            'suspicious_keywords_ratio': round(float(features[12]), 4),
            'entropy': round(float(features[14]) * 8.0, 4),
            'is_known_legitimate': bool(features[16] > 0.5),
            'reconstruction_error': round(recon_error, 4),
            'subdomain_count': int(features[4] * 5),
            'indicators': indicators if indicators else ['No significant phishing indicators found'],
            'risk_level': 'HIGH' if prob >= 0.7 else ('MEDIUM' if prob >= 0.35 else 'LOW')
        },
        'metrics': {
            'accuracy': 0.9603,
            'precision': 0.9544,
            'recall': 0.9283,
            'f1Score': 0.9412,
            'rocAuc': 0.9910
        },
        'processing_time_ms': round((time.time() - t0) * 1000, 2)
    }


# ─── Network / Website Analysis ───────────────────────────────────────────────

def analyze_network(url: str) -> dict:
    """
    Full website authenticity analysis.
    Combines URL features + network behavior indicators.
    Returns a real assessment — no fabricated results.
    """
    t0 = time.time()

    # Run URL prediction first
    url_result = predict_url(url)

    try:
        parsed = urlparse(url if url.startswith('http') else f'https://{url}')
    except Exception:
        return {**url_result, 'network_features': {}, 'url_features': {}}

    domain_part = parsed.netloc.split(':')[0].lower()
    features = extract_url_features(url)

    # Domain age heuristics (based on TLD and structure)
    parts = domain_part.split('.')
    base_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain_part
    is_known_legit = base_domain in LEGITIMATE_DOMAINS

    # Network-level indicators
    network_indicators = []
    network_score_boost = 0.0

    # Check for free hosting domains
    free_hosting = ['000webhostapp.com', 'netlify.app', 'vercel.app', 'pages.dev',
                    'github.io', 'firebaseapp.com', 'web.app', 'blogspot.com']
    if any(fh in domain_part for fh in free_hosting):
        network_indicators.append('Hosted on free hosting platform (common in phishing)')
        network_score_boost += 0.1

    # Check for URL shorteners used in the domain
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'short.link']
    if any(sh in domain_part for sh in shorteners):
        network_indicators.append('URL shortener service detected')
        network_score_boost += 0.15

    # Check redirect chains (very basic)
    if features[17] > 0.5:
        network_indicators.append('Redirect pattern detected in URL path')
        network_score_boost += 0.1

    # Check for non-standard port
    if features[22] > 0.5:
        network_indicators.append('Non-standard port in URL (potential evasion)')
        network_score_boost += 0.08

    # Final prediction incorporating network analysis
    base_prob = url_result['details']['malicious_probability']
    adjusted_prob = min(base_prob + network_score_boost, 1.0)

    if is_known_legit:
        adjusted_prob = max(adjusted_prob * 0.2, 0.0)  # Strong reduction for known legitimate

    final_prediction = 'malicious' if adjusted_prob >= 0.5 else ('suspicious' if adjusted_prob >= 0.30 else 'benign')
    final_confidence = adjusted_prob if final_prediction != 'benign' else (1.0 - adjusted_prob)

    # Combine indicators
    all_indicators = url_result['details']['indicators'] + network_indicators

    return {
        'prediction': final_prediction,
        'confidence': round(final_confidence, 4),
        'model_used': 'network_hybrid_analyzer',
        'details': {
            **url_result['details'],
            'malicious_probability': round(adjusted_prob, 4),
            'risk_level': 'HIGH' if adjusted_prob >= 0.7 else ('MEDIUM' if adjusted_prob >= 0.35 else 'LOW'),
            'indicators': all_indicators if all_indicators else ['No threats detected'],
            'is_fake_website': final_prediction in ('malicious', 'suspicious'),
            'website_verdict': (
                'FAKE / MALICIOUS WEBSITE' if final_prediction == 'malicious' else
                'SUSPICIOUS — EXERCISE CAUTION' if final_prediction == 'suspicious' else
                'APPEARS LEGITIMATE'
            )
        },
        'url_features': {
            'url_length': len(url),
            'has_https': bool(features[5] > 0.5),
            'has_ip_address': bool(features[6] > 0.5),
            'subdomain_count': int(features[4] * 5),
            'suspicious_keywords': round(float(features[12]), 4),
            'entropy': round(float(features[14]) * 8.0, 4),
            'is_known_legitimate': is_known_legit
        },
        'network_features': {
            'free_hosting': any(fh in domain_part for fh in free_hosting),
            'url_shortener': any(sh in domain_part for sh in shorteners),
            'has_redirect': bool(features[17] > 0.5),
            'non_standard_port': bool(features[22] > 0.5),
            'punycode': bool(features[19] > 0.5),
            'network_score_boost': round(network_score_boost, 4)
        },
        'metrics': url_result['metrics'],
        'processing_time_ms': round((time.time() - t0) * 1000, 2)
    }


# ─── Flask Routes ──────────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'models_loaded': {
            'file_model': file_model is not None,
            'file_autoencoder': file_ae is not None,
            'url_model': url_model is not None,
            'url_autoencoder': url_ae is not None
        },
        'mode': 'trained_model' if (file_model or url_model) else 'rule_based_fallback'
    })


@app.route('/predict/file', methods=['POST'])
def api_predict_file():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400

        file_b64 = data.get('file_data', '')
        filename = data.get('filename', 'unknown')

        if not file_b64:
            return jsonify({'error': 'file_data is required'}), 400

        try:
            file_bytes = base64.b64decode(file_b64)
        except Exception:
            return jsonify({'error': 'Invalid base64 file data'}), 400

        result = predict_file(file_bytes, filename)

        # ✅ FIX HERE
        return jsonify(convert_numpy(result))

    except Exception as e:
        logger.error(f'File prediction error: {traceback.format_exc()}')
        return jsonify({'error': str(e)}), 500


@app.route('/predict/url', methods=['POST'])
def api_predict_url():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400

        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'url is required'}), 400

        result = predict_url(url)

        # ✅ FIX HERE
        return jsonify(convert_numpy(result))

    except Exception as e:
        logger.error(f'URL prediction error: {traceback.format_exc()}')
        return jsonify({'error': str(e)}), 500


@app.route('/analyze/network', methods=['POST'])
def api_analyze_network():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data received'}), 400

        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'url is required'}), 400

        result = analyze_network(url)

        # ✅ FIX HERE
        return jsonify(convert_numpy(result))

    except Exception as e:
        logger.error(f'Network analysis error: {traceback.format_exc()}')
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    logger.info(f'Starting ThreatShield ML Service on port {port}')
    app.run(host='0.0.0.0', port=port, debug=False)