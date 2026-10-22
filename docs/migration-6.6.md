# Upgrading from REA 6.5 to 6.6

REA 6.6 keeps the `always-bump-minor` policy, including breaking releases; the
minor version increment does not imply backward compatibility. This guide
records the evidence identity change announced for saved Evidence records and
analysis snapshots.

## Evidence identity and relationship coverage

Evidence records and analysis snapshots now require an explicit nullable
`relationship_coverage` field, and the field participates in the identity
commitment behind `evidence_id`. A record that omits the field is rejected at
schema validation before any identity check, and saved files are not migrated;
preserve original files and regenerate affected observations rather than
rewriting identities.

Records exported by 6.5.0 write `relationship_coverage: null` explicitly while
omitting that null from the identity digest. Evidence verification accepts
those records again and preserves their original `evidence_id`; analysis
snapshots continue to follow the announced rule. Re-exporting the same
analysis with 6.6 computes the current identity, which includes the explicit
null, so a 6.5.0 export and a 6.6 export of one analysis keep different
`evidence_id` values.

`rea compare` across bundles from different producer generations therefore
leaves the affected records unresolved and reports `unknown` instead of an
unchanged pair, even for identical analyses. Compare bundles produced by the
same generation, or regenerate a saved bundle once with 6.6 and use the
returned identities for later comparisons.

Tamper detection is unchanged: editing semantic content fails the identity
check with `evidence_integrity_mismatch`, replacing an explicit null coverage
with a non-null value fails both identity projections, and deleting the field
fails schema validation before the identity check.
