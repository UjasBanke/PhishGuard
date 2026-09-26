# PhishGuard — interview questions & answers

**1. What problem does PhishGuard solve?**
It classifies a URL as LOW RISK, SUSPICIOUS or HIGH RISK from the URL string alone, with reasons, so a user can judge a link without opening it.

**2. Why not just visit the URL and inspect the page?**
Visiting can trigger drive-by downloads, tracking, and alerts the attacker; phishing sites also cloak content and die quickly. String analysis is safe, fast and works on a pre-click basis. It cannot see page content, which is a stated limitation.

**3. Why a hybrid of ML and rules?**
Rules are transparent and catch strong single signals (IP host, `user@host`). ML combines many weak signals and adapts by retraining. Blending gives explainability plus generalisation; the weights (0.6/0.4) are configurable.

**4. Why RandomForest?**
Tabular numeric features, mixed scales (no scaling needed), robust to outliers, little tuning, gives feature importances and calibrated-ish probabilities, and fast single-row inference.

**5. Which features matter most and why?**
Keyword count, brand-in-host, hyphens in domain, suspicious TLD, URL length. These reflect attacker tactics: keyword stuffing, brand impersonation, and cheap/abused domains.

**6. What is domain entropy and why use it?**
Shannon entropy H = −Σ p·log₂p of the characters. Algorithmically generated domains look random (higher entropy). It is weak alone and length-dependent, so the rule requires a minimum length.

**7. How do you detect brand impersonation?**
Tokenise host/userinfo/path, match brand names (with leetspeak normalisation like `paypa1`), and flag unless the registered domain is on the brand's official list. Path-only mentions score lower to avoid flagging e.g. Wikipedia articles.

**8. Why `tldextract` instead of splitting on dots?**
`co.uk`-style public suffixes make naive splitting wrong (`evil.co.uk` would count `co` as the domain). tldextract uses the Public Suffix List; PhishGuard uses its bundled snapshot so no network is needed.

**9. What is the `user@host` trick?**
In `https://paypal.com@evil.tk/`, `paypal.com` is credentials and the browser goes to `evil.tk`. It is scored as a high-severity indicator.

**10. What are punycode/homograph attacks?**
Unicode look-alike characters (Cyrillic "а") encode as `xn--…`. The host looks legitimate visually but is a different domain.

**11. Why are URL shorteners risky yet not always flagged high?**
They hide the destination, but legitimate marketing uses them too. They add moderate points rather than deciding alone.

**12. How is the final score computed?**
`risk = 0.6 × ML probability×100 + 0.4 × rule score` (rule score capped at 100). Verdicts: <35 LOW, 35–64 SUSPICIOUS, ≥65 HIGH.

**13. How do you explain an ML prediction?**
The dashboard shows an occlusion-style local explanation: replace one feature with a typical-legitimate value and see how much P(phishing) drops. It is cheap and intuitive, but it ignores feature interactions (unlike SHAP).

**14. The model scores ~99%. Is that good?**
No — the dataset is synthetic, so this only shows it learned the generator's patterns. Real evaluation needs PhishTank/OpenPhish vs Tranco data, time-based splits, and domain-disjoint train/test sets.

**15. What is data leakage here and how would you avoid it?**
The same domain, or near-duplicate URLs, appearing in both train and test inflates scores. Split by registered domain and by time.

**16. How would you handle class imbalance in production?**
Real traffic is mostly benign. Use `class_weight`, choose thresholds by precision/recall trade-off (PR curves), and evaluate at realistic prevalence. Precision matters most because false alarms erode trust.

**17. What false positives/negatives do you expect?**
False positives: legitimate login pages on unlisted brand domains, long tracking URLs. False negatives: phishing on compromised legitimate domains with clean-looking URLs.

**18. How could attackers evade it?**
Use clean short domains, HTTPS, no keywords, or compromised sites. Lexical features are cheap to evade, so real systems add domain age, certificate data, hosting/ASN, and page content.

**19. What security measures protect the app itself?**
No outbound requests to submitted URLs (tested with sockets blocked), input length/scheme/whitespace validation, HTML-escaping and no clickable links in the UI, and CSV formula-injection neutralisation on export.

**20. How would you deploy and scale it?**
Docker image with the API behind a reverse proxy; stateless inference, so scale horizontally. Load the model once at startup; batch requests use vectorised prediction. Retrain on a schedule with monitoring for drift.

**21. How do you keep the pickled model compatible?**
The bundle stores the scikit-learn version and feature order. On mismatch the loader retrains from the dataset automatically. Only load pickles you trust — unpickling can execute code.

**22. What would you add next?**
WHOIS/domain age, TLS certificate features, a reputation-feed lookup, SHAP explanations, calibration, and a browser extension.
