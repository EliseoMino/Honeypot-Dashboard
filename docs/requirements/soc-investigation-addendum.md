# SOC investigation addendum

These requirements extend the current MVP requirements for the P1/P2
investigation workflow. They preserve the single-operator, SSH-tunnel-only
deployment model.

## RF-16: Session timeline

For a selected Cowrie session, show its summary, related alerts and all
associated event metadata in ascending event time, with stable pagination.
Timeline rows must not expose passwords, raw payloads or full command lines;
the operator opens an event detail to reveal sensitive evidence deliberately.

## RF-17: Ingestion health

The agent periodically reports its liveness and tailing state over the existing
mutual TLS channel: checkpoint, log offset/size, pending records, malformed
lines, delivery failures, rotations and truncations. The backend persists the
latest heartbeat and ingestion counters in the existing spool volume. A stale
heartbeat is distinct from an idle Cowrie log. The system reports possible
loss signals and does not delete logs or uncommitted spool data automatically.

## RF-18: Reproducible and explainable detections

Each configured deterministic rule exposes its description, parameters,
severity and evidence. Fixture-based tests verify its behavior and stable
fingerprints. Rule configuration remains reviewed TOML; this phase does not add
an in-dashboard rule editor or machine-learning scoring.

## RF-19: Safe exports

The operator can download filtered event and alert CSV/JSON and an aggregate
JSON report. Exports are bounded, use allowlisted fields, exclude credentials,
raw Cowrie payloads, full command lines and operator notes by default, and
neutralize spreadsheet formula values in CSV output.

## RF-20: Optional country context

With a locally installed GeoIP country database, display an approximate country
name/code and corresponding flag beside source IPs. No IP is sent to a public
lookup service. Missing databases and unclassified addresses yield no country
value. Country context does not determine severity or attribute an actor.

## RF-21: Justified MITRE ATT&CK references

Rules may name ATT&CK tactics/techniques and provide a rationale tied to the
behavior the rule observes. The rationale accompanies the persisted finding.
Unsubstantiated rules remain unmapped; mappings are not actor attribution or
proof of activity beyond Cowrie's simulation.
