# Changelog

All notable changes to the Intuit QuickBooks CLI are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Token refresh no longer fails with "The Refresh token is invalid, please Authorize again." one hour after `auth login`. The CLI loaded only `refresh_token` into intuit-oauth, whose local expiry check then always failed before any request reached Intuit, so both automatic refresh and `auth refresh` broke once the access token expired. The refresh token's expiry is now stored at login and on each refresh (`refresh_expires_at`) and passed to intuit-oauth; tokens saved by older versions fall back to Intuit's 8726400-second lifetime.

## [0.2.4] - 2026-07-23

### Changed

- Repository renamed to `intuit/intuit-cli-for-quickbooks`. `package.json` URLs and README install instructions updated to the new canonical URL (GitHub redirects the old URL transparently).

### Security

- Bumped transitive dependencies via `npm audit fix`: `axios` to 1.17.0 and `follow-redirects` to 1.16.0, clearing one high and one moderate severity advisory.

## [0.2.3] - 2026-06-05

### Added

- Optional Premium API scope configuration via `.env`: set `INTUIT_SANDBOX_PREMIUM_SCOPES` or `INTUIT_PROD_PREMIUM_SCOPES` to a space- or comma-separated list of raw OAuth scope strings (e.g. `project-management.project`). Apps without Premium approval should leave it empty.
- `auth status` now displays the requested OAuth scopes alongside other token state, separating standard from Premium scopes.
- `--debug` output now includes the full response body (JSON pretty-printed, capped at 8KB) for both REST and GraphQL calls, making it easier to diagnose API failures.
- `custom-fields update` command — rename, activate/deactivate, or add forms to existing field definitions.

### Changed

- `auth login` now requests only standard scopes (`com.intuit.quickbooks.accounting` and `openid`) by default. Premium scopes are opt-in via `INTUIT_<env>_PREMIUM_SCOPES`. Previously all Premium scopes were requested unconditionally, which caused OAuth failures for apps without Premium API approval.
- `custom-fields create` rewritten to send the full GraphQL input the QBO server requires (`subAssociations`, `validationOptions`, `allowedOperations`). The previous schema was incomplete and every create failed.
- `--scope` flag on `custom-fields create` renamed to `--category` (matches the QBO UI category picker: customer, vendor, project, transaction).
- New `--forms` flag on `custom-fields create` controls which form types the field appears on (invoice, estimate, bill, expense, etc.). Comma-separated or repeatable.
- `projects create` mutation no longer sends `account.id` — the Premium GraphQL server infers the realm from the OAuth bearer token.
- `projects create` and `projects update` validate `--status` upfront against the actual enum values (`OPEN`, `IN_PROGRESS`, `COMPLETE`). The help text previously documented `COMPLETED`, which the server rejects.
- `items create` validates account references upfront with actionable error messages. Service and NonInventory items require `--expense-account-ref`; Service also requires `--income-account-ref`. Group items are rejected (not creatable via API). Category items reject account flags.
- `dimensions attach` filters out non-item lines (SubTotal, group summaries) that can't hold dimensions. The dry-run previously displayed them as `Line undefined`.
- GraphQL error responses with HTTP 200 status are now surfaced as errors. Previously the CLI silently returned partial data when the response body contained an `errors` field.
- `package.json` repository, homepage, and bugs URLs corrected to `github.com/intuit/intuit-cli`.

### Fixed

- README install instructions and links updated to the correct repository URL.
