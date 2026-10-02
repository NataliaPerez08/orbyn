# Cloud SKU matching

`orbyn sku-match` converts a vendor-neutral right-sizing baseline (vCPU + RAM)
into candidate instance types for a provider — the AWS / Azure / GCP step of
Phase 9 in `ORBYN_AGENT_PLAN.md`.

```bash
# Feed it the baseline suggested by an rs.* finding
orbyn assess --format json | jq '.findings[] | select(.rule_id=="rs.cpu-overprovisioned")'

orbyn sku-match --provider aws --cores 4 --ram-mb 6144
orbyn sku-match --provider azure --cores 4 --ram-mb 6144 --format json
orbyn sku-match --provider gcp  --cores 8 --ram-mb 32768 --format csv
```

Candidates are the smallest fits first (by vCPU, then RAM) that meet **both**
requirements. Output is a terminal table by default, or `--format json|csv`.

## Design

- **Separate from core right-sizing.** The assessment rules never reference a
  provider; the baseline is produced by the vendor-neutral `rs.*` rules and
  passed explicitly to `sku-match`.
- **Curated static catalogs** (`src/sku/mod.rs`) of common AWS EC2, Azure VM
  sizes and GCP machine types. They are a curated subset: a baseline with no
  fit in the catalog reports that explicitly instead of guessing.
- **Cost comparison is deferred.** On-demand list prices change by region and
  time, so they are not embedded; a live pricing source can be added behind
  the same `match_skus` shape (`ponytail:` note in `src/sku/mod.rs`).