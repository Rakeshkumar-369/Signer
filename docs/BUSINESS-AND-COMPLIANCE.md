# Business and compliance notes

> This is a practical summary for planning, not legal advice. Confirm current rules on cca.gov.in and with
> a lawyer before signing customer contracts.

## 1. Regulatory position under the IT Act, 2000

| Activity | Regulated? | Notes |
|---|---|---|
| Selling signing **software** that uses the customer's existing DSC on a USB token (this product) | **No CCA licence required** | The IT Act licenses *Certifying Authorities* (who issue certificates). Software that only uses a certificate already issued by a licensed CA is not licensed by the CCA. |
| Issuing DSCs yourself (becoming a **Certifying Authority**) | Licence from the CCA under Section 21 | Per the IT (Certifying Authorities) Rules, 2000, Rule 8: a company needs paid-up capital ≥ ₹5 crore and net worth ≥ ₹50 crore, foreign holding ≤ 49 %, full infrastructure in place before applying, and an audit by a CCA-empanelled auditor. Application fee ₹25,000. Not realistic for a start-up. |
| Offering **Aadhaar/OTP eSign** (no USB token) inside your product | No CCA licence; agreement with an eSign Service Provider (ESP) | You act as an Application Service Provider (ASP): integrate the CCA eSign API, sign an agreement with a licensed ESP, pass the ESP's onboarding audit. Per-signature charges are negotiated with the ESP. A possible future module for Signer. |

Users keep buying their Class 3 DSCs and tokens from licensed CAs (e-Mudhra, Capricorn, (n)Code, Sify,
IDRBT, Pantasign, XtraTrust, ...), exactly as today.

## 2. Product facts that help in tenders

* Signatures are standard PDF signatures (PKCS#7 / PAdES) that Adobe Acrobat and other validators verify.
* Private keys never leave the FIPS/CC-certified USB token; the product only asks the token to sign.
* Optional RFC 3161 timestamps and long-term validation (LTV) data.
* Self-hosted: documents can stay inside the department's data centre (server-prepared mode).
* Complete audit trail: who signed what, when, from which application.
* All third-party components are permissively licensed ([notices](../THIRD-PARTY-NOTICES.md)).

## 3. Licensing model (how you charge)

The platform already meters everything you need:

| Model | How it maps to Signer |
|---|---|
| **Per transaction** (pay-per-use, like the current vendor's token API) | Each issued token is a transaction; **Usage & billing** gives a monthly CSV per tenant. |
| **Subscription with quota** (e.g. up to 10,000 signatures/month) | Set *Monthly quota* on the tenant; the server refuses tokens above it. |
| **Annual site licence, on-premise** | Issue a licence file (`license issue ...`) limiting tenants and monthly volume, with an expiry date; renew yearly. |
| **Per user / per desktop** | Count distinct signers from the transaction report (signer serial numbers). |
| **AMC / support** | Annual maintenance contract for updates, driver compatibility and help-desk. |

Practical advice:

* Benchmark against quotations from existing vendors (eMudhra emSigner, Capricorn, (n)Code) obtained
  through the department or GeM rather than guessing prices.
* Government buyers prefer predictable annual pricing: offer a site licence + AMC, with pay-per-use for
  smaller departments.

## 4. Go-to-market checklist

1. **Company**: register the company; consider DPIIT "Startup India" recognition (relaxations in public
   procurement such as prior-experience and turnover criteria).
2. **Conflict of interest**: a serving government employee generally may not run a private business
   without permission under the AP Civil Services (Conduct) Rules, and selling to one's own department
   needs particular care. Obtain sanction, or have the company owned and run by someone else.
3. **Code-signing certificate** (organisation validated) to sign the agent MSI.
4. **Security audit** by a CERT-In empanelled auditor; many departments require it before go-live.
5. **GeM registration** of the product and AMC.
6. **NIC / e-Office**: e-Office is operated by NIC and the state e-Office teams. Integration of a new
   signing component with e-Office needs their approval and their changes on the e-Office side; engage
   them early with the [integration guide](INTEGRATION-GUIDE.md) and the APTS-compatible command API.
7. **Vendor licensing key**: generate it once (`license generate-keys`), keep the private key offline and
   backed up, build the public key into your releases.
8. **Support process**: help-desk checklist ([deployment guide](DEPLOYMENT.md#help-desk-checklist)),
   driver compatibility list per token model, release notes.
9. **Clean-room development**: Signer is written from public standards (PDF, CMS, PKCS#11, RFC 3161) and
   the request format published in the APTS integration document. Do not copy or decompile any vendor's
   software.

## 5. References

* Controller of Certifying Authorities – steps to become a CA: https://cca.gov.in/steps_ca.html
* IT (Certifying Authorities) Rules, 2000: https://www.wipo.int/wipolex/en/text/196537
* CCA eSign FAQ: https://www.cca.gov.in/sites/files/pdf/esign/ESIGNFAQ.pdf
* CCA eSign API specification: https://www.cca.gov.in/sites/files/pdf/ACT/eSign-APIv2.1.pdf
* CCA e-Authentication guidelines: https://cca.gov.in/sites/files/pdf/esign/CCA-EAUTH.pdf
