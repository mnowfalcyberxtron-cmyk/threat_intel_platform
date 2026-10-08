import pathlib

path = pathlib.Path('frontend/index.html')
code = path.read_text(encoding='utf-8')

# 1. Add the filter mode dropdown
if 'id="ics-filter-mode"' not in code:
    code = code.replace(
        '<select class="fi" id="ics-year"',
        '<select class="fi" id="ics-filter-mode" onchange="icsMetaLoaded=false; loadIcsCves(1)">\n          <option value="advisory">Advisory Release Date</option>\n          <option value="cve_published">CVE Published Date</option>\n        </select>\n        <select class="fi" id="ics-year"'
    )

# 2. Add the table header
if '>CVE Published</th>' not in code:
    code = code.replace(
        '<th>Published</th>',
        '<th>Adv. Published</th>\n              <th style="width:110px">CVE Published</th>'
    )

# 3. Add the table cell in renderIcsCveRows
if 'cve_published_date' not in code:
    code = code.replace(
        '<td>${published}</td>',
        '<td>${published}</td>\n      <td>${esc(r.cve_published_date ? r.cve_published_date.substring(0,10) : "N/A")}</td>'
    )

# 4. Update loadIcsMeta to use the correct lists based on mode
meta_update = """  const mode = document.getElementById('ics-filter-mode')?.value || 'advisory';
  const yearsList = mode === 'cve_published' ? meta.cve_pub_years : meta.years;
  const monthsList = mode === 'cve_published' ? meta.cve_pub_months : meta.months;
  
  // Populate year filter
  const yearSel=document.getElementById('ics-year');
  if(yearSel){
    const currentYear=yearSel.value;
    yearSel.innerHTML='<option value="">All Years</option>';
    (yearsList||[]).forEach(y=>{const o=document.createElement('option');o.value=String(y);o.textContent=String(y);yearSel.appendChild(o);});
    if(currentYear)yearSel.value=currentYear;
  }
  // Populate month filter
  const monthSel=document.getElementById('ics-month');
  if(monthSel){
    const currentMonth=monthSel.value;
    monthSel.innerHTML='<option value="">All Months</option>';
    if(monthsList && Array.isArray(monthsList)){
      monthsList.forEach(([num,name])=>{const o=document.createElement('option');o.value=String(num);o.textContent=String(name);monthSel.appendChild(o);});
    }
    if(currentMonth)monthSel.value=currentMonth;
  }"""

if 'yearsList = mode ===' not in code:
    import re
    # We replace the whole year/month population block in loadIcsMeta
    code = re.sub(
        r'// Populate year filter.*?if\(currentMonth\)monthSel\.value=currentMonth;\s*\}',
        meta_update,
        code,
        flags=re.DOTALL
    )

# 5. Update loadIcsCves to send filter_mode
if "params.set('filter_mode'" not in code:
    code = code.replace(
        "const search=document.getElementById('ics-search')?.value||'';",
        "const search=document.getElementById('ics-search')?.value||'';\n  const filter_mode=document.getElementById('ics-filter-mode')?.value||'advisory';"
    )
    code = code.replace(
        "if(search)params.set('search',search);",
        "if(search)params.set('search',search);\n  if(filter_mode)params.set('filter_mode',filter_mode);"
    )

# 6. Update the footer/source string
if 'cve_published' not in code:
    code = code.replace(
        "' | Year &amp; Month = Advisory Release Date (CVEs inside may be from any year)'",
        "(document.getElementById('ics-filter-mode')?.value === 'cve_published' ? ' | Year &amp; Month = CVE Published Date' : ' | Year &amp; Month = Advisory Release Date')"
    )

path.write_text(code, encoding='utf-8')
print('Frontend patched!')
