# Risk Register

The Risk Register records the organization's managed business risks on top of what SentinelAI detects. Sign in to
Desktop and open **Risk Register**.

## Business risk, not the technical score

**Risk** shows the calculated technical score: rule findings on each computer, weighted by deterministic policy.
**Risk Register** records administrators' business judgements about risks they manage: a risk, its owner, how likely
it is and how much harm it could do, the controls in place, the treatment decided and when it is reviewed.

The two never mix. Saving, accepting or closing a register record does not change any alert, alert status, detection
rule or technical score. Accepting a register risk is a business decision recorded with its owner and rationale; the
linked alerts keep their own lifecycle in **Alerts**.

## A record

| Field | Meaning |
| --- | --- |
| Risk ID | `R-0001`, `R-0002`, … assigned by Core, never reused. |
| Title, description | What could happen, in the organization's words. |
| Owner | A named person or role answerable for the risk. Required to accept a risk. |
| Inherent risk | Likelihood × impact from 1 to 5 each, before existing controls. |
| Existing controls | What already reduces the risk. |
| Residual risk | Likelihood × impact with the existing controls; never higher than inherent risk. |
| Treatment | Avoid, Mitigate, Transfer or Accept; may stay undecided while the risk is open. |
| Target date | When the treatment should be in place. |
| Next review | When the record is next reviewed; required unless the risk is closed. |
| Status | Open (being worked), Monitoring (treatment in place, needs a treatment) or Closed. |
| Linked computers and alerts | Enrolled computers and tracked alerts the risk concerns. |
| Tickets | External references, such as service desk tickets (up to 16). |
| History | Every change with its time, administrator, old and new values and an optional note. |

Ratings: the score is likelihood × impact. Levels are **Low** 1–4, **Medium** 5–9, **High** 10–16 and **Critical** 20–25.

## Accepting a risk

An accepted risk needs a named owner, a written rationale and an acceptance expiry date at most one year after the day
it is recorded. The expiry must be in the future whenever it is set or changed, so every acceptance is reconsidered.
Acceptance fields belong only to accepted risks.

## What needs attention

Core evaluates dates against the current UTC date and flags a record when:

- its **review is overdue** (the next review date has passed and the risk is not closed);
- its **acceptance has expired** (an accepted risk past its expiry date);
- its **target date has passed** while the risk is still open with a treatment other than Accept.

Flagged records are listed first, counted at the top of the page and selected with **Needing attention only**. Saving
other fields keeps a lapsed date visible; only a new date clears the flag. A date that is set or changed cannot already
lie in the past.

## Reviews and history

**Record a review** confirms the record still describes the risk and sets the next review date (after today), with an
optional note; the reviewer and time are kept. Closed risks are not reviewed.

Every create, change and review appends an entry to the record's history: the version, the UTC time, the administrator,
each changed field with its previous and new value, and the note. Entries are never edited or removed. Saves name the
version the administrator read; if another administrator saved in between, Core refuses the save and nothing changes,
and Desktop asks to open the record again. Desktop never repeats a save whose answer was lost.

## Filters and links

Filter by status (open and monitoring, open, monitoring, closed or all), treatment (including not decided), residual
level and attention. Links are added only to computers that are enrolled and alerts Core tracks; a link keeps working
after the computer is removed or the alert is gone, and the record says so. Desktop offers the enrolled computers and
the alerts of the ticked computers.

## Limits

- At most 2,000 records, 32 linked computers, 64 linked alerts and 16 tickets per record.
- At most 200 history entries per record; a record that reaches it takes no further changes, so close it and record a
  new one.
- Titles up to 200 characters, owners up to 128 and other texts up to 2,000; control and invisible formatting
  characters are refused.
- Records are kept in Core's local SQLite database with the rest of SentinelAI data and are included in its backups.

## API

All routes require an administrator session and a local or HTTPS connection.

| Route | Purpose |
| --- | --- |
| `GET /api/admin/risk-register` | A page of records with counts; query `status`, `treatment`, `level`, `attention`, `endpointId`, `alertId`, `offset`, `limit`. |
| `GET /api/admin/risk-register/{riskId}` | One record with its links and full history. |
| `POST /api/admin/risk-register` | Create: 201 with the record, or 422 with field error codes. |
| `PUT /api/admin/risk-register/{riskId}` | Update with `expectedVersion`: 200, 404, 409 (changed since read) or 422. |
| `POST /api/admin/risk-register/{riskId}/review` | Record a review with `expectedVersion`, `nextReviewDate` and an optional note. |
