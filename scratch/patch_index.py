import sys

with open('e:/threat_intel_platform/frontend/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add Nav Item
target_nav = '<div class="nav-item" data-view="iocs" onclick="nav(\'iocs\',this)"><span class="nav-icon">◎</span>IOC Intelligence</div>'
new_nav = target_nav + '\n    <div class="nav-item" data-view="campaigns" onclick="nav(\'campaigns\',this)"><span class="nav-icon">🚩</span>Campaign Intelligence</div>'
content = content.replace(target_nav, new_nav)

# 2. Add View HTML
target_view = '    <!-- TELEGRAM MONITOR -->'
new_view = '''    <!-- CAMPAIGNS -->
    <div id="view-campaigns" class="view">
      <div class="panel">
        <h3>Campaign Intelligence</h3>
        <p style="color:var(--muted);font-size:12px;margin-bottom:15px;">Tracking Threat Actor Campaigns (e.g., UAC, APTs) extracted from global CERT and OSINT feeds.</p>
        <div class="tw">
          <table><thead><tr><th>Campaign</th><th>IOC Count</th><th>Last Seen</th><th>Action</th></tr></thead>
          <tbody id="camp-body"><tr><td colspan="4" class="lrow"><span class="spinner"></span></td></tr></tbody>
          </table>
        </div>
      </div>
      <div class="panel" id="camp-iocs-panel" style="display:none;margin-top:20px;">
        <h3 id="camp-iocs-title">Campaign IOCs</h3>
        <div class="tw">
          <table><thead><tr><th>IOC</th><th>Type</th><th>Source</th><th>Confidence</th><th>Last Seen</th></tr></thead>
          <tbody id="camp-iocs-body"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TELEGRAM MONITOR -->'''
content = content.replace(target_view, new_view)

# 3. Add to titles dict
target_titles = "dashboard:'Dashboard',iocs:'IOC Intelligence',victims:'Ransomware Victims'"
new_titles = "dashboard:'Dashboard',campaigns:'Campaign Intelligence',iocs:'IOC Intelligence',victims:'Ransomware Victims'"
content = content.replace(target_titles, new_titles)

# 4. Add to loaders dict
target_loaders = "dashboard:loadDash,iocs:loadIOCs,victims:loadVictims"
new_loaders = "dashboard:loadDash,campaigns:loadCampaigns,iocs:loadIOCs,victims:loadVictims"
content = content.replace(target_loaders, new_loaders)

# 5. Add JS function
target_js = "// ── IOC Intelligence ─────────────────────────────────────────────────────────"
new_js = '''// ── Campaign Intelligence ────────────────────────────────────────────────────
async function loadCampaigns(){
  const data = await api('/api/campaigns');
  if(!data) return;
  let html = '';
  if(!data.campaigns || data.campaigns.length===0){
    html = '<tr><td colspan="4" class="lrow">No campaigns found yet. Wait for CERT feeds to parse.</td></tr>';
  } else {
    data.campaigns.forEach(c=>{
      html += `<tr>
        <td><strong>${escapeHTML(c.campaign)}</strong></td>
        <td><span class="badge" style="background:#555">${c.ioc_count}</span></td>
        <td>${fmtDate(c.last_seen)}</td>
        <td><button class="btn btn-sm btn-ghost" onclick="loadCampaignIOCs('${escapeHTML(c.campaign)}')">View IOCs</button></td>
      </tr>`;
    });
  }
  document.getElementById('camp-body').innerHTML = html;
  document.getElementById('camp-iocs-panel').style.display = 'none';
}

async function loadCampaignIOCs(campaignName){
  document.getElementById('camp-iocs-panel').style.display = 'block';
  document.getElementById('camp-iocs-title').innerText = 'IOCs for ' + campaignName;
  document.getElementById('camp-iocs-body').innerHTML = '<tr><td colspan="5" class="lrow"><span class="spinner"></span></td></tr>';
  const data = await api('/api/campaigns/'+encodeURIComponent(campaignName)+'/iocs');
  if(!data) return;
  let html = '';
  data.iocs.forEach(i=>{
    let src = '';
    try { src = JSON.parse(i.sources || '[]').join(', '); } catch(e){ src = i.sources; }
    html += `<tr>
      <td class="copyable" onclick="copyText(this)">${escapeHTML(i.ioc)}</td>
      <td>${escapeHTML(i.ioc_type)}</td>
      <td>${escapeHTML(src)}</td>
      <td><span class="badge badge-${i.confidence_label}">${i.confidence_label}</span></td>
      <td>${fmtDate(i.last_seen)}</td>
    </tr>`;
  });
  document.getElementById('camp-iocs-body').innerHTML = html;
}

// ── IOC Intelligence ─────────────────────────────────────────────────────────'''

content = content.replace(target_js, new_js)

with open('e:/threat_intel_platform/frontend/index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print('Patched index.html!')
