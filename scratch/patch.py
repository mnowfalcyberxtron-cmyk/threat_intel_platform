import pathlib
path = pathlib.Path('api/advisory_routes.py')
code = path.read_text(encoding='utf-8')
code = code.replace(
    'from connectors.nvd_enrichment import run_nvd_cvss4_enrichment_loop',
    'from connectors.nvd_enrichment import run_nvd_cvss4_enrichment_loop\nfrom connectors.cvelist_enrichment import build_cvelist_index, run_cvelist_enrichment_loop'
)
code = code.replace(
    '_nvd_enrichment_task: Optional[asyncio.Task] = None',
    '_nvd_enrichment_task: Optional[asyncio.Task] = None\n_cvelist_task: Optional[asyncio.Task] = None\n_cvelist_index: dict = {}'
)
code = code.replace(
    'global _nvd_enrichment_task',
    'global _nvd_enrichment_task, _cvelist_task, _cvelist_index'
)
code = code.replace(
    '_nvd_enrichment_task = asyncio.create_task(run_nvd_cvss4_enrichment_loop(_db))',
    '_nvd_enrichment_task = asyncio.create_task(run_nvd_cvss4_enrichment_loop(_db))\n    if not (_cvelist_task and not _cvelist_task.done()):\n        _cvelist_index = build_cvelist_index("cvelistV5.zip")\n        _cvelist_task = asyncio.create_task(run_cvelist_enrichment_loop(_db, _cvelist_index))'
)
code = code.replace(
    'enrich:   bool          = Query(False, description="Use AI to enrich missing patch/POC/fixed/impact fields for returned rows"),',
    'enrich:   bool          = Query(False, description="Use AI to enrich missing patch/POC/fixed/impact fields for returned rows"),\n    filter_mode: str        = Query("advisory", description="\'advisory\' or \'cve_published\'"),'
)
code = code.replace(
    'severity=severity, search=search, cve_id=search\n                )',
    'severity=severity, search=search, cve_id=search,\n                    filter_mode=filter_mode\n                )'
)
# Handle CRLF case too just in case
code = code.replace(
    'severity=severity, search=search, cve_id=search\r\n                )',
    'severity=severity, search=search, cve_id=search,\n                    filter_mode=filter_mode\n                )'
)
path.write_text(code, encoding='utf-8')
print('Patched successfully!')
