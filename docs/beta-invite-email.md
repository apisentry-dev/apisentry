# Beta Invite Email Template

**Subject:** You're in — APISentry beta access is ready 🛡️

---

Hey {{name}},

You're one of the first 200 developers to join the APISentry beta. Your access is ready.

**Here's how to get started in 3 steps:**

**1. Install the CLI**
```bash
curl -L https://apisentry.ai/install.sh | bash
```

**2. Run your first scan**
```bash
apisentry scan --spec openapi.yaml --target https://your-api.com
```

**3. Add to GitHub Actions** (optional but recommended)
```yaml
- uses: apisentry/apisentry-action@v1
  with:
    spec-path: openapi.yaml
    base-url: https://your-api.com
```

That's it. You'll see findings in under 60 seconds.

---

**What APISentry scans for:**
- BOLA / Broken Object Level Authorization (the #1 API vulnerability)
- Broken Authentication (missing token checks, JWT bypass)
- Mass Assignment (injecting `role=admin` in request bodies)
- Missing Rate Limiting (on login, password reset, OTP endpoints)
- Broken Function Level Auth (admin endpoints, HTTP method abuse)

**As a beta user you get:**
- 3 months of Pro free (normally $49/mo)
- Direct line to the founders — reply to this email with any feedback
- Your feature requests prioritized in our roadmap

---

**Join our Discord:** [discord.gg/apisentry](#)

We're a small team building this in public. Your feedback in the next 2 weeks shapes the product.

What API should you scan first? Tell us what you find.

— The APISentry Team

---

*You're receiving this because you joined the APISentry beta waitlist. [Unsubscribe](#)*
