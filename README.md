# Food Taster 🍷👑

> Kings had food tasters. Agents need one too.

For **$0.01 per request**, paid over [MPP](https://mpp.dev) (HTTP 402), Food Taster reads a web page, email, or any untrusted text **before your agent does** and checks it for prompt injection.

## API

`POST /api/taste` with `{"url": "https://..."}` or `{"text": "..."}`

Returns:

- `verdict`: one of `safe`, `suspicious` or `poisoned`
- `risk`: 0–100
- `findings`: deterministic checks covering hidden HTML, invisible unicode / tag smuggling, override phrases, exfil beacons, fake chat markup and payment coercion
- `classifier`: Claude's verdict. The content is passed strictly as data inside delimited tags
- `cleaned_text`: the visible text with hidden elements, comments and invisible characters removed

Discovery: `/openapi.json` (with `x-payment-info`) and `/llms.txt`.

```bash
npx mppx https://<host>/api/taste --method POST --json-body '{"url":"https://example.com"}' --network testnet
```

## Security notes

- URL fetches are SSRF-safe. Each address is checked inside the socket's DNS lookup, which blocks private, loopback, link-local and metadata ranges with no rebinding window. Only ports 80/443 are allowed, there are at most 3 redirects (each one re-checked), and fetches are capped at 1 MB and 8 s.
- Bad input is rejected before you pay.
- Secrets (`MPP_SECRET_KEY`, `ANTHROPIC_API_KEY`) live only in host environment variables, never in the repo.

## Run

Requires `MPP_SECRET_KEY`, `TEMPO_RECIPIENT` and `ANTHROPIC_API_KEY`. Optional: `PUBLIC_URL`, `TASTER_MODEL`, `PRICE_USD`, and `TEMPO_MAINNET=true`.

```bash
npm install && npm start
```

Built for the MPP Hackathon (Tempo × Stripe).
