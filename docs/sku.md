# Cloud SKU matching

`orbyn sku-match` converts a vendor-neutral right-sizing baseline (vCPU + RAM)
into candidate instance types for a provider.

```bash
# Feed it the baseline suggested by an rs.* finding
orbyn assess --format json | jq '.findings[] | select(.rule_id=="rs.cpu-overprovisioned")'

orbyn sku-match --provider aws --cores 4 --ram-mb 6144
orbyn sku-match --provider azure --cores 4 --ram-mb 6144 --format json
orbyn sku-match --provider gcp  --cores 8 --ram-mb 32768 --format csv
orbyn sku-match --provider huawei --cores 4 --ram-mb 8192
orbyn sku-match --provider openstack --cores 4 --ram-mb 8192
```

Candidates are the smallest fits first (by vCPU, then RAM) that meet **both**
requirements. Output is a terminal table by default, or `--format json|csv`.
Any loaded catalog provider works — the embedded set (aws, azure, gcp,
huawei, openstack) plus anything installed into the runtime catalog
directory.

## Design

- **Separate from core right-sizing.** The assessment rules never reference a
  provider; the baseline is produced by the vendor-neutral `rs.*` rules and
  passed explicitly to `sku-match`.
- **Provider-neutral catalogs** (`data/catalogs/*.json`, embedded at build
  time): capability rows (SKUs) and price rows are strictly separate and join
  on SKU name. A new provider arrives as catalog data, never as engine code.
  OpenStack ships reference flavors without prices — sizing works, pricing
  stays honestly `not_calculated` (private-cloud pricing is site-specific).
- **Freshness as data packages.** A runtime catalog directory
  (`ORBYN_CATALOG_DIR`, default `./data/catalogs/`) overrides the embedded
  catalogs per provider; `orbyn catalog install --file` and
  `orbyn catalog update --url` maintain it. Prices are curated on-demand list
  price snapshots with a retrieval date — estimates, never quotes.
