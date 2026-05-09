
/* ═══════════════════════════════════════════════════════════
   CyberXTron TIP v2 — Dashboard with AI Integration
   No external redirects. All analysis is local.
═══════════════════════════════════════════════════════════ */

let curView='dashboard', iocPage=1, vicPage=1, repMD='', logTimer=null, alertTab='';
const COLORS=['#00d4ff','#388bfd','#bc8cff','#3fb950','#d29922','#db6d28','#f85149','#ff7ab2'];

// ── Utilities ───────────────────────────────────────────────────────────────
async function api(path,opts={}){
  try{
    opts.headers = opts.headers || {};
    const storedKeys = localStorage.getItem('cyberxtron_keys');
    if (storedKeys) opts.headers['X-API-Keys'] = storedKeys;
    const r=await fetch(path,opts);
    let data=null; try { data=await r.json(); } catch(e){}
    if(!r.ok){
      const msg = data?.detail || data?.error || 'HTTP '+r.status;
      toast(msg,'err');
      return null;
    }
    return data;
  }catch(e){console.error(path,e);toast(e.message,'err');return null;}
}
const fmt=n=>n!=null?Number(n).toLocaleString():'—';
const fdt=s=>s?s.slice(0,10):'—';
const fts=s=>s?s.replace('T',' ').slice(0,16)+' UTC':'—';
const esc=s=>{const d=document.createElement('div');d.textContent=s||'';return d.innerHTML};
let _dt={};
function debounce(fn,ms){return function(...a){clearTimeout(_dt[fn]);_dt[fn]=setTimeout(()=>fn(...a),ms);}}
function toast(msg,type='info'){
  const c=document.getElementById('toasts');
  const t=document.createElement('div');t.className=`toast ${type}`;t.textContent=msg;
  c.appendChild(t);setTimeout(()=>t.remove(),3500);
}
function mdToHTML(md){
  if(!md)return '';
  return md
    .replace(/^# (.+)$/gm,'<h1>$1</h1>')
    .replace(/^## (.+)$/gm,'<h2>$1</h2>')
    .replace(/^### (.+)$/gm,'<h3>$1</h3>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/`([^`]+)`/g,'<code>$1</code>')
    .replace(/^\| (.+) \|$/gm, line => {
      const cells = line.split('|').filter(c => c.trim() && !c.trim().match(/^[-\s]+$/));
      return cells.length ? '<tr>' + cells.map(c => `<td>${c.trim()}</td>`).join('') + '</tr>' : '';
    })
    .replace(/(<tr>.*?<\/tr>[\s\S]*?)+/g, m => `<table>${m}</table>`)
    .replace(/^- (.+)$/gm,'<li>$1</li>')
    .replace(/(<li>[\s\S]+?<\/li>)+/g,m=>'<ul>'+m+'</ul>')
    .replace(/^\d+\. (.+)$/gm,'<li>$1</li>')
    .replace(/^---$/gm,'<hr>')
    .replace(/\n\n/g,'<br>');
}

// ── Navigation ───────────────────────────────────────────────────────────────
function nav(view, el){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  document.getElementById('view-'+view).classList.add('active');
  if(el)el.classList.add('active');
  curView=view;
  const titles={dashboard:'Dashboard',iocs:'IOC Intelligence',victims:'Ransomware Victims',
    alerts_intel:'General Intelligence Alerts', alerts_darkweb:'Dark Web Monitor Alerts',
    advisory:'AI Advisory & Reports',chat:'AI Analyst Chat',
    sources:'Data Sources',logs:'Activity Logs',advisories:'Company Security Advisories',livefeed:'Live Threat Intelligence Feed'};
  document.getElementById('page-title').textContent=titles[view]||view;
  ({dashboard:loadDash,iocs:loadIOCs,victims:loadVictims,
    alerts_intel:loadAlertsIntel, alerts_darkweb:loadAlertsDarkWeb,
    ransomware:loadRL,'darkweb-mgr':loadDarkwebMgr,advisories:loadAdvisories,hibr:loadHIBR,
    advisory:loadSavedReports,sources:loadSources,logs:loadLogs,livefeed:loadFeed,chat:loadChatModel})[view]?.();
}

// ── AI Status ────────────────────────────────────────────────────────────────
async function loadAIStatus(){
  const [status, health] = await Promise.all([
    api('/api/ai/provider/status'),
    api('/api/ai/health')
  ]);
  if(!status) return;

  const badge = document.getElementById('ai-provider-badge');
  const statusTxt = document.getElementById('ai-status-txt');
  const chatModel = document.getElementById('chat-model');

  // Build dots for each provider
  const providerDots = health ? Object.entries(health).map(([p, s]) => {
    const active = p === status.provider;
    const ok = s.status === 'ok';
    const color = ok ? 'var(--green)' : (s.status === 'not_configured' ? 'var(--muted)' : 'var(--red)');
    const label = p === 'groq' ? 'GROQ' : p === 'openrouter' ? 'OR' : p.toUpperCase();
    return `<span title="${p}: ${s.status}${s.code ? ' ('+s.code+')' : ''}" style="display:inline-flex;align-items:center;gap:3px;margin-right:6px;font-size:10px;font-weight:${active?'800':'500'};color:${active?'var(--cyan)':'var(--muted)'}">`+
      `<span style="width:6px;height:6px;border-radius:50%;background:${color};display:inline-block;${ok&&active?'box-shadow:0 0 6px '+color:''};"></span>`+
      `${label}${active?' ✦':''}</span>`;
  }).join('') : '';

  const activeOk = health?.[status.provider]?.status === 'ok';
  badge.innerHTML = `<span style="display:inline-flex;align-items:center;gap:5px">`+
    `<span style="color:${activeOk?'var(--cyan)':'var(--yellow)'};font-size:11px;font-weight:700">⬡ AI:</span>`+
    providerDots +
    `</span>`;

  // Truncate model name nicely
  const modelShort = (status.model || status.provider).split('/').pop().replace(':free','');
  statusTxt.textContent = `${status.provider.toUpperCase()} — ${modelShort} — ${activeOk ? 'ONLINE' : 'CHECKING...'}`;
  if(chatModel) chatModel.textContent = status.model || status.provider;
}
function loadChatModel(){ loadAIStatus(); }
async function openAIModal(){
  openModal('ai-settings-modal');
  const data = await api('/api/ai/provider/status');
  if(data) document.getElementById('ai-provider-select').value = data.provider;
  checkAIHealth();
}
async function checkAIHealth(){
  const c = document.getElementById('ai-health-list');
  c.innerHTML = '<div class="lrow"><span class="spinner"></span> Checking connectivity...</div>';
  const health = await api('/api/ai/health');
  const status = await api('/api/ai/provider/status');
  if(!health){c.innerHTML='<div class="empty">Failed to fetch health</div>';return;}
  c.innerHTML = Object.entries(health).map(([p,s])=>{
    const ok = s.status === 'ok';
    const active = p === status?.provider;
    const dotClass = ok ? 'ok' : (s.status==='not_configured'?'':'error');
    const modelName = active ? `<span style="font-size:9px;color:var(--muted)"> — ${(status.model||'').split('/').pop()}</span>` : '';
    return `<div style="display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--border);align-items:center">`+
      `<div style="display:flex;gap:8px;align-items:center">`+
        `<div class="src-dot ${dotClass}" style="width:8px;height:8px;animation:${ok?'pulse 2s infinite':'none'}"></div>`+
        `<div style="font-size:11px;font-weight:700;color:${active?'var(--cyan)':'var(--txt)'}">${p.toUpperCase()}${active?' (ACTIVE)':''}</div>`+
        modelName+
      `</div>`+
      `<div style="font-size:10px;font-weight:600;color:${ok?'var(--green)':s.status==='not_configured'?'var(--muted)':'var(--red)'}">`+
        `${ok?'ONLINE':(s.status==='not_configured'?'NOT SET':'OFFLINE')} ${s.code?'('+s.code+')':''}`+
      `</div>`+
    `</div>`;
  }).join('');
}
async function saveAIProvider(){
  const p = document.getElementById('ai-provider-select').value;
  const res = await api('/api/ai/provider/select?provider='+p,{method:'POST'});
  if(res?.status==='success'){
    toast(`AI Provider switched to ${p.toUpperCase()}`,'ok');
    loadAIStatus();
    checkAIHealth();
  }
}

// ── Dashboard ────────────────────────────────────────────────────────────────
async function loadDash(){
  const s=await api('/api/stats');
  if(!s)return;
  document.getElementById('s0').textContent=fmt(s.total_iocs);
  document.getElementById('s1').textContent=fmt(s.high_confidence_iocs);
  document.getElementById('s2').textContent=fmt(s.total_victims);
  document.getElementById('s3').textContent=fmt((s.unacknowledged_alerts_intel||0) + (s.unacknowledged_alerts_darkweb||0));
  document.getElementById('s4').textContent=fmt(s.new_iocs_24h);
  document.getElementById('s5').textContent=fmt(s.new_victims_24h);
  document.getElementById('alert-intel-count').textContent=s.unacknowledged_alerts_intel||0;
  document.getElementById('alert-darkweb-count').textContent=s.unacknowledged_alerts_darkweb||0;
  renderActivityChart(s.daily_ioc_activity||[]);
  renderTypeChart(s.ioc_type_distribution||[]);
  renderGroups(s.top_ransomware_groups||[]);
  renderActorsTable(s.top_threat_actors||[]);
  const alerts=await api('/api/alerts?limit=5');
  renderRecentAlerts(alerts||[]);
  document.getElementById('last-updated').textContent='Updated '+new Date().toLocaleTimeString();
}

function renderActivityChart(data){
  const c=document.getElementById('activity-chart');
  if(!data.length){c.innerHTML='<div class="empty" style="width:100%">No activity yet</div>';return;}
  const mx=Math.max(...data.map(d=>d.cnt),1);
  c.innerHTML=data.map((d,i)=>{
    const h=Math.max(Math.round(d.cnt/mx*140),2);
    return `<div class="bar-wrap"><div class="bar" style="height:${h}px;background:${COLORS[i%COLORS.length]};opacity:.85" title="${d.day||''}: ${d.cnt} IOCs"></div><div class="bar-lbl">${(d.day||'').slice(5)}</div></div>`;
  }).join('');
}
function renderTypeChart(data){
  const c=document.getElementById('type-chart');
  const clrs={ip:'#388bfd',domain:'#00d4ff',url:'#bc8cff',md5:'#db6d28',sha256:'#d29922',sha1:'#f85149',cve:'#f85149',email:'#3fb950'};
  const tot=data.reduce((s,d)=>s+d.cnt,0)||1;
  c.innerHTML=data.slice(0,8).map(d=>{
    const pct=Math.round(d.cnt/tot*100);
    const col=clrs[d.ioc_type]||'#8b949e';
    return `<div style="width:100%;margin-bottom:6px"><div style="display:flex;justify-content:space-between;font-size:10px;margin-bottom:2px"><span class="badge b-${d.ioc_type}">${d.ioc_type}</span><span style="color:var(--muted)">${fmt(d.cnt)} (${pct}%)</span></div><div style="background:var(--bg);border-radius:2px;height:3px"><div style="background:${col};width:${pct}%;height:3px;border-radius:2px;transition:width .5s"></div></div></div>`;
  }).join('');
}
function renderGroups(groups){
  const c=document.getElementById('groups-list');
  if(!groups.length){c.innerHTML='<div class="empty" style="padding:16px">No data yet</div>';return;}
  c.innerHTML=groups.slice(0,8).map(g=>
    `<div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid var(--border);cursor:pointer" onclick="openActorModal('${esc(g.group_name)}')">
      <span class="gtag" style="cursor:pointer">${esc(g.group_name)}</span>
      <span style="font-family:var(--mono);font-size:11px;color:var(--red)">${fmt(g.victims)}</span>
    </div>`
  ).join('');
}
function renderActorsTable(actors){
  const tb=document.getElementById('actors-table');
  document.getElementById('actors-badge').textContent=actors.length;
  tb.innerHTML=actors.length?actors.map(a=>
    `<tr class="clickable" onclick="openActorModal('${esc(a.threat_actor)}')">
      <td style="color:var(--cyan)">${esc(a.threat_actor)}</td>
      <td class="mono">${fmt(a.cnt)}</td>
      <td><button class="btn btn-ai btn-sm" onclick="event.stopPropagation();openActorModal('${esc(a.threat_actor)}')">⬡ Profile</button></td>
    </tr>`
  ).join(''):
  '<tr><td colspan="3" class="empty" style="padding:16px">No actors tracked yet</td></tr>';
}
function renderRecentAlerts(alerts){
  const c=document.getElementById('recent-alerts');
  if(!alerts.length){c.innerHTML='<div class="empty" style="padding:24px"><div class="empty-ico">✓</div><div class="empty-txt">No alerts</div></div>';return;}
  c.innerHTML=alerts.slice(0,5).map(alertHTML).join('');
}

// ── IOC Intelligence ─────────────────────────────────────────────────────────
async function loadIOCs(){
  const p=new URLSearchParams({page:iocPage,page_size:50});
  const add=(id,k)=>{const v=document.getElementById(id)?.value;if(v)p.set(k,v);};
  add('ioc-q','search');add('ioc-type','ioc_type');add('ioc-conf','confidence');
  add('ioc-src','source');add('ioc-actor','threat_actor');add('ioc-from','date_from');
  document.getElementById('ioc-body').innerHTML='<tr><td colspan="8" class="lrow"><span class="spinner"></span></td></tr>';
  const data=await api('/api/iocs?'+p);
  if(!data)return;
  document.getElementById('ioc-count').textContent=fmt(data.total)+' IOCs';
  const tb=document.getElementById('ioc-body');
  if(!data.items?.length){
    tb.innerHTML='<tr><td colspan="8"><div class="empty"><div class="empty-ico">◎</div><div class="empty-txt">No IOCs match filters</div><div class="empty-sub">Feeds may still be loading — click "Fetch All Feeds"</div></div></td></tr>';
    return;
  }
  tb.innerHTML=data.items.map(ioc=>{
    let srcs;try{srcs=JSON.parse(ioc.sources||'[]');}catch{srcs=[];}
    const srcStr=srcs.slice(0,2).join(', ')+(srcs.length>2?` +${srcs.length-2}`:'');
    return `<tr class="clickable" onclick="openIOCModal(${ioc.id})">
      <td class="mono" style="color:var(--txt);max-width:320px;word-break:break-all;white-space:normal;font-size:${ioc.ioc_type==='domain'&&ioc.ioc.includes('.onion')?'9px':'11px'}" title="${esc(ioc.ioc)}">${esc(ioc.ioc)}</td>
      <td><span class="badge b-${ioc.ioc_type}">${ioc.ioc_type}</span></td>
      <td><span class="badge ${ioc.confidence_label==='high'?'bh':ioc.confidence_label==='medium'?'bm':'bl'}">${ioc.confidence_label} ${(ioc.confidence*100).toFixed(0)}%</span></td>
      <td style="font-size:10px;color:var(--txt2)">${esc(srcStr)}</td>
      <td style="font-size:10px;color:var(--orange)">${esc(ioc.malware||'—')}</td>
      <td style="font-size:10px;color:var(--cyan);cursor:pointer" onclick="event.stopPropagation();openActorModal('${esc(ioc.threat_actor)}')">${ioc.threat_actor!=='unknown'?esc(ioc.threat_actor):'—'}</td>
      <td style="font-size:10px;color:var(--muted)">${fdt(ioc.last_seen)}</td>
      <td><button class="btn btn-ai btn-sm" onclick="event.stopPropagation();openIOCModal(${ioc.id})">⬡ Analyze</button></td>
    </tr>`;
  }).join('');
  paginate('ioc-pager',data.total,iocPage,50,p=>{iocPage=p;loadIOCs();});
}
function clearIOCFilters(){
  ['ioc-q','ioc-type','ioc-conf','ioc-src','ioc-actor','ioc-from'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});
  iocPage=1;loadIOCs();
}

// ── Victims ──────────────────────────────────────────────────────────────────
async function loadVictims(){
  const p=new URLSearchParams({page:vicPage,page_size:50});
  const add=(id,k)=>{const v=document.getElementById(id)?.value;if(v)p.set(k,v);};
  add('vic-q','search');add('vic-grp','group_name');add('vic-cty','country');add('vic-from','date_from');add('vic-src','source');
  document.getElementById('vic-body').innerHTML='<tr><td colspan="10" class="lrow"><span class="spinner"></span></td></tr>';
  const data=await api('/api/victims?'+p);
  if(!data)return;
  document.getElementById('vic-count').textContent=fmt(data.total)+' victims';
  const tb=document.getElementById('vic-body');
  if(!data.items?.length){
    tb.innerHTML='<tr><td colspan="10"><div class="empty"><div class="empty-ico">☠</div><div class="empty-txt">No victims yet</div><div class="empty-sub">Ransomware.live and RansomWatch data loads on startup</div></div></td></tr>';
    return;
  }
  tb.innerHTML=data.items.map(v=>{
    const srcMap = { 'haveibeenransom': 'HIBR', 'ransomware_live': 'Ransom.live' };
    const srcDisp = srcMap[v.source] || v.source || '—';
    const srcLink = v.source_url && !v.source_url.includes('.onion') ? v.source_url : '#';
    const hasLeakDate = v.leak_date && v.leak_date.trim();
    const leakDateCell = hasLeakDate
      ? `<span style="color:var(--txt2)">${fdt(v.leak_date)}</span>`
      : `<span style="background:rgba(248,81,73,.1);color:var(--red);border:1px solid rgba(248,81,73,.2);padding:1px 6px;border-radius:4px;font-size:8px;font-weight:700">NO DATE</span>`;
    const sizeCell = v.data_size && v.data_size.trim()
      ? `<span style="color:var(--orange);font-weight:600">${esc(v.data_size)}</span>`
      : `<span style="color:var(--muted);font-size:9px">Not reported</span>`;
    return `<tr class="clickable" onclick="openVictimModal(${v.id})">
      <td style="font-weight:600;max-width:180px" class="trunc" title="${esc(v.victim_name)}">${esc(v.victim_name)}</td>
      <td><span class="gtag" style="cursor:pointer" onclick="event.stopPropagation();openActorModal('${esc(v.group_name)}')">${esc(v.group_name)}</span></td>
      <td style="font-size:10px">${v.country && v.country.trim() ? `<span class="badge bl">${esc(v.country)}</span>` : '<span style="color:var(--muted);font-size:9px">Not specified</span>'}</td>
      <td style="font-size:10px;color:var(--txt2)">${v.industry && v.industry.trim() ? esc(v.industry) : '<span style="color:var(--muted);font-size:9px">Not specified</span>'}</td>
      <td style="font-size:10px;color:var(--muted)">${fdt(v.discovery_date)}</td>
      <td style="font-size:10px">${leakDateCell}</td>
      <td style="font-size:10px">${sizeCell}</td>
      <td style="font-size:10px">
        ${(()=>{
          let link = v.source_url;
          if(!link || link.includes('.onion')) {
            if(v.source==='haveibeenransom') link = 'https://haveibeenransom.com/';
            else link = 'https://www.ransomware.live/';
          }
          const disp = v.source==='haveibeenransom'?'HIBR':'Ransom.live';
          return `<a href="${esc(link)}" target="_blank" style="color:var(--cyan);text-decoration:none;font-weight:600" onclick="event.stopPropagation()">${esc(disp)} ↗</a>`;
        })()}
      </td>
      <td>${v.onion_url ?
        `<span class="mono" style="font-size:9px;color:var(--purple)" title="${esc(v.onion_url)}">${esc(v.onion_url.slice(7,37))}…</span>`
        :'<span style="color:var(--muted);font-size:9px">—</span>'}</td>
      <td><button class="btn btn-ai btn-sm" onclick="event.stopPropagation();openVictimModal(${v.id})">⬡ Intel</button></td>
    </tr>`;
  }).join('');
  paginate('vic-pager',data.total,vicPage,50,p=>{vicPage=p;loadVictims();});
}
function clearVicFilters(){
  ['vic-q','vic-grp','vic-cty','vic-from','vic-src'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';});
  vicPage=1;loadVictims();
}

// ── Modals ───────────────────────────────────────────────────────────────────
function openModal(id){document.getElementById(id).classList.add('open');}
function closeModal(id){document.getElementById(id).classList.remove('open');}
function switchTab(modal, tab, el){
  document.querySelectorAll(`#${modal}-modal .modal-tab-content`).forEach(t=>t.classList.remove('active'));
  document.querySelectorAll(`#${modal}-modal .mtab`).forEach(t=>t.classList.remove('active'));
  document.getElementById(`${modal}-tab-${tab}`).classList.add('active');
  if(el)el.classList.add('active');
}

// IOC Modal
async function openIOCModal(iocId){
  openModal('ioc-modal');
  document.getElementById('ioc-modal-title').textContent='Loading IOC...';
  document.getElementById('ioc-tab-data').innerHTML='<div class="lrow"><span class="spinner"></span></div>';
  document.getElementById('ioc-ai-content').innerHTML='<div class="ai-loading"><span class="spinner"></span> Ready — click "AI Analysis" tab to analyze</div>';
  // Reset tabs
  document.querySelectorAll('#ioc-modal .mtab').forEach((t,i)=>{t.classList.toggle('active',i===0);});
  document.querySelectorAll('#ioc-modal .modal-tab-content').forEach((t,i)=>{t.classList.toggle('active',i===0);});

  const data=await api(`/api/iocs/${iocId}`);
  if(!data){document.getElementById('ioc-tab-data').innerHTML='<div class="empty">IOC not found</div>';return;}
  document.getElementById('ioc-modal-title').textContent=data.ioc;
  const srcs=Array.isArray(data.sources)?data.sources:[];
  const tags=Array.isArray(data.tags)?data.tags:[];
  document.getElementById('ioc-tab-data').innerHTML=`
    <div style="margin-bottom:12px"><span class="badge b-${data.ioc_type}" style="font-size:11px;padding:3px 10px">${data.ioc_type}</span>
    <span class="badge ${data.confidence_label==='high'?'bh':data.confidence_label==='medium'?'bm':'bl'}" style="margin-left:6px;font-size:11px">${data.confidence_label} confidence — ${(data.confidence*100).toFixed(0)}%</span></div>
    ${dr('IOC Value',`<span class="mono" style="color:var(--cyan);word-break:break-all">${esc(data.ioc)}</span>`)}
    ${dr('Type',data.ioc_type)}
    ${dr('Malware',data.malware||'unknown')}
    ${dr('Malware Family',data.malware_family||'—')}
    ${dr('Threat Actor',data.threat_actor!=='unknown'?`<span style="color:var(--cyan);cursor:pointer" onclick="closeModal('ioc-modal');openActorModal('${esc(data.threat_actor)}')">${esc(data.threat_actor)} ↗</span>`:data.threat_actor)}
    ${dr('Campaign',data.campaign||'—')}
    ${dr('Sources',srcs.join(', ')||'—')}
    ${dr('Source Count',data.source_count||1)}
    ${dr('Tags',tags.length?tags.map(t=>`<span class="badge bl" style="margin:1px">${esc(t)}</span>`).join(' '):'none')}
    ${dr('First Seen',fts(data.first_seen))}
    ${dr('Last Seen',fts(data.last_seen))}
    ${dr('Severity',data.severity||'medium')}
    ${dr('Description',esc(data.description||'none'))}
  `;
  // Wire AI tab to lazy-load
  document.querySelector('#ioc-modal .mtab:nth-child(2)').onclick=function(){
    switchTab('ioc','ai',this);
    loadIOCAI(iocId);
  };
}

async function loadIOCAI(iocId){
  const c=document.getElementById('ioc-ai-content');
  if(c.dataset.loaded===String(iocId))return;
  c.innerHTML='<div class="ai-loading"><span class="spinner"></span> Analyzing with CyberXTron AI...</div>';
  const data=await api(`/api/ai/analyze/ioc/${iocId}`);
  c.dataset.loaded=String(iocId);
  c.innerHTML=data?.analysis?mdToHTML(data.analysis):'<div style="color:var(--yellow)">AI analysis unavailable — configure AI provider in .env</div>';
}

// Actor Modal
async function openActorModal(actorName){
  if(!actorName||actorName==='unknown'||actorName==='—')return;
  openModal('actor-modal');
  document.getElementById('actor-modal-title').textContent=actorName;
  document.getElementById('actor-tab-data').innerHTML='<div class="lrow"><span class="spinner"></span></div>';
  document.getElementById('actor-ai-content').innerHTML='<div class="ai-loading"><span class="spinner"></span> Ready — click "AI Profile" tab</div>';
  document.querySelectorAll('#actor-modal .mtab').forEach((t,i)=>t.classList.toggle('active',i===0));
  document.querySelectorAll('#actor-modal .modal-tab-content').forEach((t,i)=>t.classList.toggle('active',i===0));

  const iocData=await api(`/api/iocs?threat_actor=${encodeURIComponent(actorName)}&page_size=20`);
  const vicData=await api(`/api/victims?group_name=${encodeURIComponent(actorName)}&page_size=20`);
  const iocs=iocData?.items||[];
  const victims=vicData?.items||[];

  const typeCounts={};
  iocs.forEach(i=>{typeCounts[i.ioc_type]=(typeCounts[i.ioc_type]||0)+1;});

  document.getElementById('actor-tab-data').innerHTML=`
    <div style="display:flex;gap:12px;margin-bottom:14px;flex-wrap:wrap">
      <div class="stat-card" style="flex:1;min-width:100px;padding:10px">
        <div class="stat-label">Total IOCs</div><div class="stat-val" style="font-size:20px">${fmt(iocData?.total||0)}</div>
      </div>
      <div class="stat-card" style="flex:1;min-width:100px;padding:10px">
        <div class="stat-label">Victims</div><div class="stat-val" style="font-size:20px;color:var(--red)">${fmt(vicData?.total||0)}</div>
      </div>
    </div>
    <div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">IOC Breakdown</div>
    ${Object.entries(typeCounts).map(([t,c])=>`<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid var(--border);font-size:11px"><span class="badge b-${t}">${t}</span><span class="mono">${c}</span></div>`).join('')||'<div style="color:var(--muted)">No IOCs</div>'}
    <div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin:14px 0 8px">Recent IOCs</div>
    ${iocs.slice(0,10).map(i=>`<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid rgba(33,38,45,.4);font-size:10px"><span class="badge b-${i.ioc_type}">${i.ioc_type}</span><span class="mono" style="flex:1;color:var(--cyan);word-break:break-all;font-size:10px">${esc(i.ioc)}</span><span style="color:var(--orange)">${esc(i.malware||'')}</span></div>`).join('')||'<div style="color:var(--muted)">No IOCs tracked</div>'}
    <div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin:14px 0 8px">Recent Victims</div>
    ${victims.slice(0,8).map(v=>`<div style="display:flex;gap:8px;padding:4px 0;border-bottom:1px solid rgba(33,38,45,.4);font-size:10px"><span style="flex:1;font-weight:600">${esc(v.victim_name)}</span><span style="color:var(--muted)">${esc(v.country||'')} ${fdt(v.discovery_date)}</span></div>`).join('')||'<div style="color:var(--muted)">No victims tracked</div>'}
  `;

  document.querySelector('#actor-modal .mtab:nth-child(2)').onclick=function(){
    switchTab('actor','ai',this);
    loadActorAI(actorName);
  };
}

async function loadActorAI(name){
  const c=document.getElementById('actor-ai-content');
  if(c.dataset.loaded===name)return;
  c.innerHTML='<div class="ai-loading"><span class="spinner"></span> Profiling threat actor with AI...</div>';
  const data=await api(`/api/ai/analyze/actor/${encodeURIComponent(name)}`);
  c.dataset.loaded=name;
  c.innerHTML=data?.analysis?mdToHTML(data.analysis):'<div style="color:var(--yellow)">Configure AI provider in .env to enable analysis</div>';
}

// Victim Modal
async function openVictimModal(vidId){
  openModal('victim-modal');
  document.getElementById('victim-modal-title').textContent='Loading...';
  document.getElementById('victim-tab-data').innerHTML='<div class="lrow"><span class="spinner"></span></div>';
  document.getElementById('victim-ai-content').innerHTML='<div class="ai-loading"><span class="spinner"></span> Ready — click "AI Analysis" tab</div>';
  document.getElementById('victim-group-content').innerHTML='<div class="ai-loading"><span class="spinner"></span> Ready — click "Group Profile" tab</div>';
  document.querySelectorAll('#victim-modal .mtab').forEach((t,i)=>t.classList.toggle('active',i===0));
  document.querySelectorAll('#victim-modal .modal-tab-content').forEach((t,i)=>t.classList.toggle('active',i===0));

  // Fetch victim from victims list endpoint
  const data=await api(`/api/victims?page_size=1000`);
  const victim=data?.items?.find(v=>v.id===vidId);
  if(!victim){document.getElementById('victim-tab-data').innerHTML='<div class="empty">Not found</div>';return;}
  document.getElementById('victim-modal-title').textContent=victim.victim_name;
  document.getElementById('victim-tab-data').innerHTML=`
    <div style="margin-bottom:12px"><span class="gtag">${esc(victim.group_name)}</span></div>
    ${dr('Victim',`<strong style="color:var(--txt)">${esc(victim.victim_name)}</strong>`)}
    ${dr('Ransomware Group',`<span style="color:var(--red);cursor:pointer" onclick="closeModal('victim-modal');openActorModal('${esc(victim.group_name)}')">${esc(victim.group_name)} ↗</span>`)}
    ${dr('Country',victim.country||'—')}
    ${dr('Industry',victim.industry||'—')}
    ${dr('Website',victim.website?`<a href="${esc(victim.website)}" target="_blank" style="color:var(--blue)">${esc(victim.website)}</a>`:'—')}
    ${dr('Discovery Date',fts(victim.discovery_date))}
    ${dr('Leak Date',fts(victim.leak_date)||'—')}
    ${dr('Data Size',victim.data_size||'—')}
    ${dr('Status',victim.status||'published')}
    ${dr('Source Feed',(()=>{
      let link = victim.source_url;
      if(!link || link.includes('.onion')) {
        if(victim.source==='haveibeenransom') link = 'https://haveibeenransom.com/';
        else link = 'https://www.ransomware.live/';
      }
      const disp = victim.source==='haveibeenransom'?'HIBR / RansomWatch':'Ransomware.live';
      return `<a href="${esc(link)}" target="_blank" style="color:var(--cyan);font-weight:600">${esc(disp)} ↗</a>`;
    })())}
    ${dr('.onion Link', victim.onion_url ? `<span class="mono" style="color:var(--purple)">${esc(victim.onion_url)}</span>` : '—')}
    ${dr('Description',`<span style="color:var(--txt2)">${esc(victim.description||'none')}</span>`)}
  `;

  document.querySelector('#victim-modal .mtab:nth-child(2)').onclick=function(){
    switchTab('victim','ai',this);loadVictimAI(vidId);
  };
  document.querySelector('#victim-modal .mtab:nth-child(3)').onclick=function(){
    switchTab('victim','group',this);loadGroupAI(victim.group_name);
  };
}

async function loadVictimAI(vidId){
  const c=document.getElementById('victim-ai-content');
  if(c.dataset.loaded===String(vidId))return;
  c.innerHTML='<div class="ai-loading"><span class="spinner"></span> Analyzing breach with AI...</div>';
  const data=await api(`/api/ai/analyze/victim/${vidId}`);
  c.dataset.loaded=String(vidId);
  c.innerHTML=data?.analysis?mdToHTML(data.analysis):'<div style="color:var(--yellow)">Configure AI provider in .env</div>';
}
async function loadGroupAI(groupName){
  const c=document.getElementById('victim-group-content');
  if(c.dataset.loaded===groupName)return;
  c.innerHTML='<div class="ai-loading"><span class="spinner"></span> Profiling ransomware group...</div>';
  const data=await api(`/api/ai/analyze/group/${encodeURIComponent(groupName)}`);
  c.dataset.loaded=groupName;
  c.innerHTML=data?.analysis?mdToHTML(data.analysis):'<div style="color:var(--yellow)">Configure AI provider in .env</div>';
}

function dr(k,v){return `<div class="data-row"><div class="data-key">${k}</div><div class="data-val">${v}</div></div>`;}

// ── Alerts ────────────────────────────────────────────────────────────────────
function alertHTML(a){
  const isDarkWeb = ['onion_status_change', 'onion_new_active', 'darkweb_monitor'].includes(a.alert_type);
  let desc = esc((a.description||'').slice(0,300));
  if(isDarkWeb) {
    desc = desc.replace(/(http:\/\/[\w\.]+\.onion)/g, '<span style="color:var(--purple);font-family:var(--mono);font-size:10px;background:rgba(188,140,255,.1);padding:2px 5px;border-radius:4px;border:1px solid rgba(188,140,255,.2);margin:2px 0;display:inline-block">$1</span>');
  }
  return `<div class="alert-item ${a.acknowledged?'acked':''}" id="al-${a.id}">
    <div class="al-bar ${a.severity||'medium'}"></div>
    <div class="al-body">
      <div class="al-title" style="${isDarkWeb?'color:var(--purple);font-weight:700':''}">${esc(a.title)}</div>
      <div class="al-desc">${desc}</div>
      <div class="al-meta">${fts(a.created_at)} · ${a.source||'platform'}</div>
    </div>
    <div style="display:flex;gap:5px;align-items:center">
      <span class="badge ${a.severity==='critical'?'bc':a.severity==='high'?'bc':a.severity==='medium'?'bm':'bh'}">${a.severity}</span>
      ${!a.acknowledged?`<button class="btn btn-ghost btn-sm" onclick="ackAlert(${a.id})">✓</button>`:'<span style="font-size:9px;color:var(--muted)">acked</span>'}
    </div>
  </div>`;
}

async function loadAlertsIntel(){
  const unacked=document.getElementById('unacked-intel')?.checked;
  const data=await api(`/api/alerts?unacknowledged_only=${unacked}&alert_type=general&limit=200`);
  document.getElementById('alert-intel-count').textContent=data?.filter(a=>!a.acknowledged).length||0;
  const c=document.getElementById('alert-intel-list');
  if(!data?.length){c.innerHTML='<div class="empty" style="padding:36px"><div class="empty-ico">✓</div><div class="empty-txt">No general alerts</div></div>';return;}
  c.innerHTML=data.map(alertHTML).join('');
}

async function loadAlertsDarkWeb(){
  const unacked=document.getElementById('unacked-darkweb')?.checked;
  const data=await api(`/api/alerts?unacknowledged_only=${unacked}&alert_type=darkweb&limit=200`);
  document.getElementById('alert-darkweb-count').textContent=data?.filter(a=>!a.acknowledged).length||0;
  const c=document.getElementById('alert-darkweb-list');
  if(!data?.length){c.innerHTML='<div class="empty" style="padding:36px"><div class="empty-ico">🌑</div><div class="empty-txt">No dark web alerts</div><div class="empty-sub">Accurate .onion monitoring alerts appear here</div></div>';return;}
  c.innerHTML=data.map(alertHTML).join('');
}

async function ackAlert(id){
  await api('/api/alerts/acknowledge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_id:id})});
  document.getElementById('al-'+id)?.classList.add('acked');
  if(curView==='alerts_intel') loadAlertsIntel();
  else if(curView==='alerts_darkweb') loadAlertsDarkWeb();
  else if(curView==='dashboard') loadDash();
  toast('Alert acknowledged','ok');
}
async function ackAll(){
  await api('/api/alerts/acknowledge-all',{method:'POST'});
  loadAlerts();toast('All alerts acknowledged','ok');
}

// ── AI Advisory ───────────────────────────────────────────────────────────────
document.getElementById('adv-type').addEventListener('change',function(){
  document.getElementById('adv-actor-wrap').style.display=this.value==='advisory'?'none':'block';
});

async function genAdvisory(){
  const type=document.getElementById('adv-type').value;
  const actor=document.getElementById('adv-actor').value.trim();
  const days=parseInt(document.getElementById('adv-days').value);
  if(type!=='advisory'&&!actor){toast('Enter actor/group name','err');return;}
  const btn=document.getElementById('adv-btn');
  btn.textContent='✦ Generating...';btn.disabled=true;
  document.getElementById('rep-viewer').innerHTML='<div class="ai-loading" style="font-size:13px;padding:30px"><span class="spinner"></span> CyberXTron AI is analyzing your threat intelligence database...</div>';

  let data;
  if(type==='advisory'){
    data=await api('/api/ai/advisory',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({days})});
    repMD=data?.advisory||'';
    document.getElementById('rep-viewer').innerHTML=mdToHTML(repMD)||'<div style="color:var(--yellow)">Configure AI provider in .env</div>';
  } else if(type==='actor'){
    data=await api(`/api/ai/analyze/actor/${encodeURIComponent(actor)}`);
    repMD=data?.analysis||'';
    document.getElementById('rep-viewer').innerHTML=mdToHTML(repMD)||'<div style="color:var(--yellow)">No data for this actor or AI not configured</div>';
  } else {
    data=await api(`/api/ai/analyze/group/${encodeURIComponent(actor)}`);
    repMD=data?.analysis||'';
    document.getElementById('rep-viewer').innerHTML=mdToHTML(repMD)||'<div style="color:var(--yellow)">No data for this group or AI not configured</div>';
  }

  btn.textContent='✦ Generate AI Report';btn.disabled=false;
  document.getElementById('copy-btn').style.display='inline-flex';
  loadSavedReports();
  toast('Report generated','ok');
}

function copyReport(){navigator.clipboard.writeText(repMD);toast('Copied to clipboard','ok');}

async function loadSavedReports(){
  const data=await api('/api/reports');
  const c=document.getElementById('saved-reports');
  if(!data?.length){c.innerHTML='<div class="empty"><div class="empty-ico">📄</div><div class="empty-txt">No reports yet</div></div>';return;}
  c.innerHTML=data.map(r=>`<div class="rep-card" onclick="viewReport(${r.id})">
    <div style="flex:1"><div style="font-size:12px;font-weight:600">${esc(r.title)}</div>
    <div style="font-size:10px;color:var(--muted);margin-top:2px">${fts(r.generated_at)} · ${r.threat_actor||'—'}</div></div>
    <span style="color:var(--muted)">›</span>
  </div>`).join('');
}
async function viewReport(id){
  const data=await api(`/api/reports/${id}/markdown`);
  if(data?.markdown){repMD=data.markdown;document.getElementById('rep-viewer').innerHTML=mdToHTML(repMD);document.getElementById('copy-btn').style.display='inline-flex';}
}

// ── AI Chat ───────────────────────────────────────────────────────────────────
async function sendChat(){
  const inp=document.getElementById('chat-in');
  const msg=inp.value.trim();
  if(!msg)return;
  inp.value='';
  const msgs=document.getElementById('chat-msgs');
  msgs.innerHTML+=`<div class="msg user">${esc(msg)}</div>`;
  msgs.innerHTML+=`<div class="msg ai" id="ai-typing"><span class="spinner"></span> Analyzing...</div>`;
  msgs.scrollTop=msgs.scrollHeight;
  const data=await api('/api/ai/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg})});
  const typing=document.getElementById('ai-typing');
  if(typing)typing.outerHTML=`<div class="msg ai">${mdToHTML(data?.response||'⚠️ AI provider not configured correctly. Check AI_PROVIDER and API keys in .env')}</div>`;
  msgs.scrollTop=msgs.scrollHeight;
}

// ── Sources ────────────────────────────────────────────────────────────────────
async function loadSources(){
  const srcs=await api('/api/sources');
  const g=document.getElementById('src-grid');
  if(!srcs?.length){g.innerHTML='<div class="empty">No sources</div>';return;}
  g.innerHTML=srcs.map(s=>{
    const dc=s.status==='ok'?'ok':s.status==='error'?'error':s.enabled?'pending':'disabled';
    return `<div class="src-card">
      <div class="src-dot ${dc}"></div>
      <div><div class="src-name">${esc(s.display_name)}</div>
      <div class="src-meta">Tier ${s.tier} · ${(s.status||'pending').toUpperCase()}</div>
      <div class="src-meta">Records: ${fmt(s.total_records)}</div>
      <div class="src-meta">Last: ${s.last_fetched?fts(s.last_fetched):'Never'}</div>
      ${s.error_msg?`<div class="src-meta" style="color:var(--red)">${esc(s.error_msg.slice(0,50))}</div>`:''}</div>
    </div>`;
  }).join('');
  const sched=await api('/api/scheduler/status');
  const tb=document.getElementById('jobs-tbody');
  tb.innerHTML=(sched?.jobs||[]).map(j=>`<tr><td style="font-weight:600">${esc(j.name)}</td><td style="font-size:10px;color:var(--muted)">${j.next_run?fts(j.next_run):'—'}</td></tr>`).join('')||'<tr><td colspan="2" style="color:var(--muted);padding:10px">No jobs</td></tr>';
}

// ── Logs ────────────────────────────────────────────────────────────────────────
async function loadLogs(){
  const lvl=document.getElementById('log-lvl')?.value;
  const p=new URLSearchParams({limit:400});
  if(lvl)p.set('level',lvl);
  const data=await api('/api/logs?'+p);
  const c=document.getElementById('log-body');
  if(!data?.length){c.innerHTML='<div class="empty" style="padding:16px">No logs</div>';return;}
  const lvlColor={INFO:'var(--cyan)',ERROR:'var(--red)',WARNING:'var(--yellow)',DEBUG:'var(--muted)'};
  c.innerHTML=data.map(l=>`<div style="display:flex;gap:10px;padding:4px 0;border-bottom:1px solid rgba(33,38,45,.35);font-size:10px">
    <span style="color:var(--muted);flex-shrink:0">${fts(l.timestamp)}</span>
    <span style="color:${lvlColor[l.level]||'var(--muted)'};width:50px;flex-shrink:0;font-weight:700">${l.level}</span>
    <span style="color:var(--blue);flex-shrink:0;width:100px;overflow:hidden;text-overflow:ellipsis">${esc(l.source)}</span>
    <span style="color:var(--txt2)">${esc(l.message)}</span>
  </div>`).join('');
}

// ── Global ─────────────────────────────────────────────────────────────────────
function paginate(id,total,page,size,cb){
  const c=document.getElementById(id);
  const pages=Math.ceil(total/size);
  if(pages<=1){c.innerHTML='';return;}
  c.innerHTML=`<button class="btn btn-ghost btn-sm" ${page<=1?'disabled':''} onclick="(${cb})(${page-1})">← Prev</button><div class="spacer">Page ${page} of ${pages} (${fmt(total)})</div><button class="btn btn-ghost btn-sm" ${page>=pages?'disabled':''} onclick="(${cb})(${page+1})">Next →</button>`;
}
async function refresh(){({dashboard:loadDash,iocs:loadIOCs,victims:loadVictims,alerts:loadAlerts,advisory:loadSavedReports,advisories:loadAdvisories,sources:loadSources,logs:loadLogs,livefeed:loadFeed,ransomware:loadRL,'darkweb-mgr':loadDarkwebMgr,hibr:loadHIBR,chat:loadChatModel})[curView]?.();toast('Refreshed','info');}
async function runAll(){
  toast('Triggering all feeds (runs in background)...','info');
  await api('/api/refresh',{method:'POST'});
  toast('All connectors triggered — data loads in ~2 min','ok');
  setTimeout(loadDash,5000);
}


// ── HIBR Investigation ──────────────────────────────────────────────────────
async function loadHIBR(){
  const status = await api('/api/hibr/status');
  const bar = document.getElementById('hibr-status-bar');
  if(!status){bar.innerHTML='<span style="color:var(--red)">HIBR API unreachable</span>';return;}
  if(!status.configured){
    bar.innerHTML=`<span style="color:var(--yellow)">⚠ HIBR not configured.</span> Add <code>HIBR_API_KEY=your_key</code> and <code>ENABLE_HIBR=true</code> to <code>.env</code>, then restart.`;
    return;
  }
  bar.innerHTML=`<span style="color:var(--green)">✓ HIBR Connected</span> &nbsp;|&nbsp; Total breaches in HIBR DB: <strong>${fmt(status.total_breaches_in_hibr||0)}</strong> &nbsp;|&nbsp; Your plan: Active`;
}

async function hibrInvestigateDomain(){
  const domain=document.getElementById('hibr-domain').value.trim();
  if(!domain){toast('Enter a domain','err');return;}
  const c=document.getElementById('hibr-domain-result');
  c.innerHTML='<div class="lrow"><span class="spinner"></span> Investigating '+esc(domain)+'...</div>';
  const data=await api('/api/hibr/investigate/domain/'+encodeURIComponent(domain));
  if(!data){c.innerHTML='<div style="color:var(--red)">Request failed — check HIBR configuration</div>';return;}
  c.innerHTML=renderHIBRInvestigation(data);
}

async function hibrInvestigateEmail(){
  const email=document.getElementById('hibr-email').value.trim();
  if(!email){toast('Enter an email','err');return;}
  const c=document.getElementById('hibr-email-result');
  c.innerHTML='<div class="lrow"><span class="spinner"></span> Investigating '+esc(email)+'...</div>';
  const data=await api('/api/hibr/investigate/email/'+encodeURIComponent(email));
  if(!data){c.innerHTML='<div style="color:var(--red)">Request failed</div>';return;}
  c.innerHTML=renderHIBREmailResult(data);
}

async function hibrMetaSearch(){
  const field=document.getElementById('hibr-meta-field').value;
  const query=document.getElementById('hibr-meta-query').value.trim();
  if(!query){toast('Enter search term','err');return;}
  const c=document.getElementById('hibr-meta-result');
  c.innerHTML='<div class="lrow"><span class="spinner"></span></div>';
  const data=await api('/api/hibr/search/metadata/'+field+'/'+encodeURIComponent(query));
  if(!data){c.innerHTML='<div style="color:var(--red)">Search failed</div>';return;}
  const results=data.results||[];
  if(!results.length){c.innerHTML='<div class="empty" style="padding:16px"><div class="empty-txt">No results found</div></div>';return;}
  c.innerHTML=`<div style="font-size:10px;color:var(--muted);margin-bottom:8px">Found ${fmt(data.pagination?.total_sources||results.length)} sources | Page ${data.pagination?.current_page||1} of ${data.pagination?.total_pages||1}</div>`+
    results.map(r=>`<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:10px;margin-bottom:7px;font-size:11px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <span class="gtag">${esc(r.group_name||'?')}</span>
        <span style="color:var(--muted)">${fdt(r.discovered)}</span>
      </div>
      <div style="font-weight:600;color:var(--txt);margin-bottom:3px">${esc(r.post_title||'?')}</div>
      <div style="color:var(--txt2)">${esc(r.website||'')} ${r.country?'· '+esc(r.country):''}</div>
      <div style="color:var(--yellow);margin-top:4px">Identities: ${fmt(r['Identities Found']||0)}</div>
      ${r.post_url?`<div style="margin-top:4px;font-size:10px;color:var(--muted);word-break:break-all" title="Onion URL stored locally">Source: ${esc(r.post_url.slice(0,60))}...</div>`:''}
    </div>`).join('');
}

async function hibrStealerSearch(){
  const field=document.getElementById('hibr-stealer-field').value;
  const query=document.getElementById('hibr-stealer-query').value.trim();
  if(!query){toast('Enter search term','err');return;}
  const c=document.getElementById('hibr-stealer-result');
  c.innerHTML='<div class="lrow"><span class="spinner"></span></div>';
  const data=await api('/api/hibr/search/fullstealer/'+field+'/'+encodeURIComponent(query));
  if(!data){c.innerHTML='<div style="color:var(--red)">Search failed</div>';return;}
  const results=data.data||[];
  if(!results.length){c.innerHTML='<div class="empty" style="padding:16px"><div class="empty-txt">No stealer logs found</div></div>';return;}
  c.innerHTML=`<div style="font-size:10px;color:var(--yellow);margin-bottom:8px">⚠ ${fmt(data.total_hits||results.length)} infostealer log entries found</div>`+
    results.slice(0,10).map(r=>`<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:9px;margin-bottom:6px;font-size:10px;font-family:var(--mono)">
      ${r.email?`<div><span style="color:var(--muted)">email:</span> <span style="color:var(--cyan)">${esc(r.email)}</span></div>`:''}
      ${r.password?`<div><span style="color:var(--muted)">pass:</span> <span style="color:var(--red)">${esc(r.password)}</span></div>`:''}
      ${r.domain?`<div><span style="color:var(--muted)">domain:</span> ${esc(r.domain)}</div>`:''}
      ${r.wallets?.length?`<div><span style="color:var(--muted)">wallets:</span> <span style="color:var(--orange)">${esc(r.wallets.join(', '))}</span></div>`:''}
      ${r.hwid?`<div><span style="color:var(--muted)">hwid:</span> ${esc(r.hwid)}</div>`:''}
      ${r.source_metadata?.malware_family?`<div style="margin-top:4px"><span class="badge bc">${esc(r.source_metadata.malware_family)}</span> ${esc(r.source_metadata.country||'')} ${fdt(r.source_metadata.infection_date||'')}</div>`:''}
    </div>`).join('');
}

function renderHIBRInvestigation(data){
  const meta=data.metadata||{};
  const fd=data.fulldata_summary||{};
  const st=data.stealer_summary||{};
  const results=meta.results||[];
  let html=`
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:14px">
      <div class="stat-card c-cyan" style="padding:12px"><div class="stat-label">Breach Incidents</div><div class="stat-val" style="font-size:20px">${fmt(results.length)}</div></div>
      <div class="stat-card c-red" style="padding:12px"><div class="stat-label">Exposed Identities</div><div class="stat-val" style="font-size:20px;color:var(--orange)">${fmt(fd.total_hits||0)}</div></div>
      <div class="stat-card c-yellow" style="padding:12px"><div class="stat-label">Stealer Log Entries</div><div class="stat-val" style="font-size:20px;color:var(--yellow)">${fmt(st.total_hits||0)}</div></div>
    </div>`;

  if(results.length){
    html+=`<div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Breach History</div>`;
    html+=results.slice(0,5).map(r=>`<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:10px;margin-bottom:7px">
      <div style="display:flex;justify-content:space-between"><span class="gtag">${esc(r.group_name||'?')}</span><span style="font-size:10px;color:var(--muted)">${fdt(r.discovered)}</span></div>
      <div style="font-size:12px;font-weight:600;margin-top:5px;color:var(--txt)">${esc(r.post_title||'?')}</div>
      <div style="font-size:10px;color:var(--yellow);margin-top:3px">${fmt(r['Identities Found']||0)} identities exposed</div>
    </div>`).join('');
  }

  if(data.ai_analysis){
    html+=`<div style="font-size:10px;font-weight:700;color:var(--purple);text-transform:uppercase;letter-spacing:1px;margin:14px 0 8px">⬡ AI Intelligence Assessment</div>`;
    html+=`<div class="ai-output">${mdToHTML(data.ai_analysis)}</div>`;
  }
  return html;
}

function renderHIBREmailResult(data){
  const fd=data.fulldata||{};
  const st=data.stealer||{};
  let html=`
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">
      <div class="stat-card c-red" style="padding:12px"><div class="stat-label">Breach Records</div><div class="stat-val" style="font-size:20px">${fmt(fd.total_hits||0)}</div></div>
      <div class="stat-card c-yellow" style="padding:12px"><div class="stat-label">Stealer Logs</div><div class="stat-val" style="font-size:20px;color:var(--yellow)">${fmt(st.total_hits||0)}</div></div>
    </div>`;

  const recs=[...(fd.records||[]),...(st.records||[])].slice(0,8);
  if(recs.length){
    html+=`<div style="font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Exposed Data</div>`;
    html+=recs.map(r=>`<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:9px;margin-bottom:6px;font-size:10px;font-family:var(--mono)">
      ${r.source_metadata?.group_name?`<span class="gtag" style="margin-bottom:6px;display:inline-block">${esc(r.source_metadata.group_name)}</span><br>`:''}
      ${r.source_metadata?.company_affected?`<span style="font-weight:600;color:var(--txt)">${esc(r.source_metadata.company_affected)}</span><br>`:''}
      ${r.email_context?`<span style="color:var(--txt2)">${esc(r.email_context)}</span><br>`:''}
      ${r.password?`<span style="color:var(--muted)">pass: </span><span style="color:var(--red)">${esc(r.password)}</span><br>`:''}
      ${r.source_metadata?.malware_family?`<span class="badge bc">${esc(r.source_metadata.malware_family)}</span>`:''}
    </div>`).join('');
  }

  if(data.ai_analysis){
    html+=`<div style="font-size:10px;font-weight:700;color:var(--purple);text-transform:uppercase;letter-spacing:1px;margin:14px 0 8px">⬡ AI Assessment</div>`;
    html+=`<div class="ai-output">${mdToHTML(data.ai_analysis)}</div>`;
  }
  return html;
}


// ── Ransomware.live ──────────────────────────────────────────────────────────
async function loadRL(){
  const status = await api('/api/rl/status');
  const bar = document.getElementById('rl-status-bar');
  if(status){
    const tier = status.tier || 'public';
    const keySet = status.api_key_set;
    bar.innerHTML = keySet
      ? `<span style="color:var(--green)">✓ Ransomware.live: <strong>${esc(tier)}</strong></span>`
      : `<span style="color:var(--yellow)">⚠ Ransomware.live: Public API (free). Add RANSOMWARE_LIVE_API_KEY for Pro features.</span>`;
  }
  loadRLGroups();
  loadRLVictims();
}

async function loadRLGroups(){
  const data = await api('/api/rl/groups');
  const c = document.getElementById('rl-groups-list');
  const groups = data?.groups || [];
  document.getElementById('rl-group-count').textContent = groups.length + ' groups';
  if(!groups.length){
    c.innerHTML='<div class="empty" style="padding:20px"><div class="empty-txt">No group data yet</div><div class="empty-sub">Will populate after first Ransomware.live fetch</div></div>';
    return;
  }
  c.innerHTML = groups.slice(0,50).map(g => {
    const name = g.name || g.group_name || '?';
    const status = g.status || g.active || 'active';
    const locations = (g.locations || []).length;
    return `<div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid var(--border);cursor:pointer" onclick="openActorModal('${esc(name)}')">
      <div>
        <span class="gtag">${esc(name)}</span>
        <span style="font-size:9px;color:var(--muted);margin-left:6px">${locations} sites · ${esc(status)}</span>
      </div>
      <button class="btn btn-ai btn-sm" onclick="event.stopPropagation();openActorModal('${esc(name)}')">⬡ Intel</button>
    </div>`;
  }).join('');
}

async function loadRLVictims(){
  const data = await api('/api/rl/victims/recent?limit=50');
  const c = document.getElementById('rl-victims-list');
  const victims = data?.victims || [];
  if(!victims.length){
    c.innerHTML='<div class="empty" style="padding:20px"><div class="empty-txt">No recent victims yet</div></div>';
    return;
  }
  c.innerHTML = victims.slice(0,30).map(v => {
    const group = v.group_name || v.group || '?';
    const victim = v.post_title || v.victim || v.company || '?';
    const country = v.country || '';
    const date = v.published || v.date || '';
    return `<div style="padding:7px 0;border-bottom:1px solid var(--border)">
      <div style="display:flex;justify-content:space-between;align-items:flex-start">
        <span style="font-weight:600;font-size:12px;color:var(--txt)">${esc(victim)}</span>
        <span style="font-size:9px;color:var(--muted)">${fdt(date)}</span>
      </div>
      <div style="display:flex;gap:6px;margin-top:3px">
        <span class="gtag" style="cursor:pointer" onclick="openActorModal('${esc(group)}')">${esc(group)}</span>
        ${country?`<span style="font-size:10px;color:var(--muted)">${esc(country)}</span>`:''}
      </div>
    </div>`;
  }).join('');
}

async function rlSearch(){
  const q = document.getElementById('rl-search-q').value.trim();
  if(!q){toast('Enter search term','err');return;}
  const c = document.getElementById('rl-search-result');
  c.innerHTML='<div class="lrow"><span class="spinner"></span></div>';
  const data = await api('/api/rl/victims/search/'+encodeURIComponent(q));
  if(!data){c.innerHTML='<div style="color:var(--red)">Search failed — Pro API required</div>';return;}
  const results = data.results || [];
  if(!results.length){c.innerHTML='<div class="empty" style="padding:16px"><div class="empty-txt">No results for "'+esc(q)+'"</div></div>';return;}
  c.innerHTML=`<div style="font-size:10px;color:var(--muted);margin-bottom:8px">${fmt(results.length)} results for "${esc(q)}"</div>`+
    results.map(r=>`<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:9px;margin-bottom:6px">
      <div style="font-weight:600;color:var(--txt)">${esc(r.post_title||r.victim||r.company||'?')}</div>
      <div style="display:flex;gap:8px;margin-top:3px;font-size:10px">
        <span class="gtag">${esc(r.group_name||r.group||'?')}</span>
        <span style="color:var(--muted)">${esc(r.country||'')} ${fdt(r.published||r.date||'')}</span>
      </div>
    </div>`).join('');
}

async function rlTriggerScan(){
  toast('Triggering Ransomware.live fetch...','info');
  await api('/api/refresh',{method:'POST'});
  toast('Feed refresh triggered','ok');
  setTimeout(()=>{loadRLVictims();loadRLGroups();},8000);
}

// ── Dark Web Manager ─────────────────────────────────────────────────────────
async function loadDarkwebMgr(){
  checkTor();
  await loadDWSites();
  loadOnionMonitor();
  dwAutoTestAll(); // auto-test all pending/unchecked .onion links in background
  loadDWResults();
}

// ── Onion Status Monitor ─────────────────────────────────────────────────────
async function loadOnionMonitor() {
  const data = await api('/api/onion/status');
  if(!data) return;

  // Header Summary
  const s = data.summary;
  document.getElementById('onion-summary-bar').innerHTML = 
    `<strong>${s.total}</strong> Monitored &nbsp;|&nbsp; ` + 
    `<strong style="color:var(--green)">${s.online}</strong> Online &nbsp;|&nbsp; ` +
    `<strong style="color:var(--red)">${s.offline}</strong> Offline &nbsp;|&nbsp; ` +
    `${s.pending} Pending`;

  // Stats Grid
  document.getElementById('onion-status-stats').innerHTML = `
    <div class="stat-card c-cyan"><div class="stat-label">Total Sites</div><div class="stat-val">${s.total}</div></div>
    <div class="stat-card c-green"><div class="stat-label">Verified Online</div><div class="stat-val">${s.online}</div></div>
    <div class="stat-card c-red"><div class="stat-label">Down / Error</div><div class="stat-val">${s.offline}</div></div>
    <div class="stat-card c-yellow"><div class="stat-label">Pending Scan</div><div class="stat-val">${s.pending}</div></div>
  `;

  // Online / Offline Lists
  const renderList = (sites, color) => sites.length ? sites.map(site => `
    <div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--r);padding:6px 9px;margin-bottom:6px;display:flex;justify-content:space-between;align-items:center;font-size:10px">
      <div>
        <span class="gtag">${esc(site.group_name)}</span>
        <div style="color:var(--muted);margin-top:3px;font-family:var(--mono)">${esc(site.url)}</div>
        ${site.screenshot_path ? `<div style="margin-top:4px"><a href="/screenshots/${site.screenshot_path.split(/[\\\/]/).pop()}" target="_blank" style="color:var(--cyan);text-decoration:none;font-weight:600">📸 View Screenshot</a></div>` : ''}
        ${site.full_html ? `<div style="font-size:8px;color:var(--txt2);margin-top:3px">HTML Size: ${(site.full_html.length/1024).toFixed(1)} KB</div>` : ''}
      </div>
      <div style="text-align:right">
        <span style="color:${color};font-weight:700">${site.last_status==='200'?'ONLINE':site.last_status==='pending'?'PENDING':'OFFLINE'}</span>
        <div style="color:var(--muted);font-size:9px;margin-top:2px">${site.last_checked ? fst(site.last_checked) : ''}</div>
      </div>
    </div>`).join('') : '<div class="empty" style="padding:10px"><div class="empty-txt">No sites in this category</div></div>';

  document.getElementById('onion-online-list').innerHTML = renderList(data.online_sites, 'var(--green)');
  document.getElementById('onion-offline-list').innerHTML = renderList(data.offline_sites, 'var(--red)');

  // Changes
  if(data.recent_changes && data.recent_changes.length) {
    document.getElementById('onion-changes-section').style.display = 'block';
    document.getElementById('onion-changes-list').innerHTML = data.recent_changes.map(c => 
      `<div style="font-size:10px;padding:5px 0;border-bottom:1px solid var(--border);display:flex;justify-content:space-between">
         <span style="color:var(--txt2)">${esc(c.description)}</span>
         <span style="color:var(--muted)">${fst(c.created_at)}</span>
       </div>`
    ).join('');
  }
}

async function triggerOnionScan() {
  toast('Triggering background Tor scan...', 'info');
  await api('/api/onion/scan', {method: 'POST'});
  toast('Scan initiated. It may take some time depending on Tor latency.', 'ok');
  setTimeout(loadOnionMonitor, 5000);
}

// Helper to format short time
const fst = s => { try { return s ? s.replace('T', ' ').slice(11, 16) : ''; } catch(e) { return ''; } };

// Auto-test ONLY sites that have NEVER been checked (no status at all)
// IMPORTANT: Never re-test sites that already have a confirmed '200' status
async function dwAutoTestAll(){
  const data = await api('/api/darkweb/sites');
  if(!data) return;
  const allSites = [
    ...(data.config_sites||[]).map(s=>({...s, editable:false, id:s.id})),
    ...(data.user_sites||[]).map(s=>({...s, editable:true, id:s.id})),
    ...(data.discovered_sites||[]).map(s=>({...s, editable:false, id:s.id})),
  ];
  // ONLY test sites that have NEVER been checked (null/pending) - NEVER overwrite confirmed '200' results!
  const toTest = allSites.filter(s => !s.last_status || s.last_status === 'pending');
  if(!toTest.length){ return; }
  toast(`Testing ${toTest.length} unchecked .onion sites...`, 'info');
  let completed = 0;
  for(const s of toTest){
    api('/api/darkweb/sites/'+s.id+'/test', {method:'POST'})
      .then(result => {
        completed++;
        if(completed % 3 === 0 || completed === toTest.length) loadDWSites();
      })
      .catch(()=>{});
    await new Promise(r => setTimeout(r, 800));
  }
}

async function checkTor(){
  const bar = document.getElementById('dw-tor-status');
  bar.innerHTML = '<span class="spinner"></span> Checking Tor...';
  const data = await api('/api/darkweb/tor/status');
  if(!data){ bar.innerHTML='<span style="color:var(--red)">Could not check Tor status</span>'; return; }
  if(data.tor_running){
    bar.innerHTML=`<span style="color:var(--green)">✓ Tor Running</span> &nbsp;|&nbsp; Exit IP: <strong>${esc(data.exit_ip)}</strong> &nbsp;|&nbsp; Proxy: ${esc(data.proxy)} &nbsp;|&nbsp; Dark web monitoring is <strong style="color:var(--green)">active</strong>`;
  } else {
    const guide = data.install_guide || {};
    bar.innerHTML=`<span style="color:var(--red)">✗ Tor Not Running</span> &nbsp;|&nbsp; ${esc(data.error||'Not reachable')} &nbsp;·&nbsp; <span style="color:var(--muted)">Linux: <code>sudo apt install tor && sudo systemctl start tor</code></span>`;
  }
}

async function loadDWSites(){
  const data = await api('/api/darkweb/sites');
  const c = document.getElementById('dw-sites-list');
  if(!data){c.innerHTML='<div style="color:var(--red)">Failed to load sites</div>';return;}

  const allSites = [
    ...(data.config_sites||[]).map(s=>({...s, editable:false, category:'config'})),
    ...(data.user_sites||[]).map(s=>({...s, editable:true, id:s.id, category:'user'})),
    ...(data.discovered_sites||[]).map(s=>({...s, editable:false, category:'discovered'})),
  ];
  document.getElementById('dw-site-count').textContent = allSites.length + ' sites monitored (' + (data.active_count||0) + ' active)';

  // Categories for display
  // Active = confirmed HTTP 200 response (any source)
  const active      = allSites.filter(s => String(s.last_status) === '200');
  // Pending = never tested (null/pending) - for non-discovered sites
  const pending     = allSites.filter(s => (!s.last_status || s.last_status === 'pending') && s.category !== 'discovered');
  // Newly discovered active (from intel feeds but confirmed 200)
  const discoveredActive = allSites.filter(s => s.category === 'discovered' && String(s.last_status) === '200');
  // Newly discovered unverified (pending or failed)
  const discoveredNew = allSites.filter(s => s.category === 'discovered' && String(s.last_status) !== '200');
  // Offline = only user/config sites that definitively failed
  const offline     = allSites.filter(s => {
    if (s.category === 'discovered') return false; // discovered shown in their own section
    if (!s.last_status || s.last_status === 'pending') return false;
    if (String(s.last_status) === '200') return false;
    return true;
  });

  const statusBadge = (s) => {
    const st = String(s.last_status||'');
    if (st === '200') return '<span style="color:var(--green);font-weight:700;font-size:10px">● ACTIVE</span>';
    if (!s.last_status || st === 'pending') return '<span style="color:var(--cyan);font-weight:700;font-size:10px">◌ PENDING</span>';
    return '<span style="color:var(--red);font-weight:700;font-size:10px">✗ OFFLINE</span>';
  };

    renderSiteRow = (s) => `<tr style="border-bottom:1px solid rgba(33,38,45,.4)">
          <td style="padding:8px">${statusBadge(s)}</td>
          <td style="padding:8px"><span class="gtag">${esc(s.group_name)}</span>${!s.editable?'<span style="font-size:8px;color:var(--muted);margin-left:4px">default</span>':''}</td>
          <td style="padding:8px"><span class="mono" style="font-size:9px;color:var(--txt2);word-break:break-all">${esc(s.url)}</span></td>
          <td style="padding:8px;font-size:10px;color:var(--muted)">${s.last_checked?fts(s.last_checked):'Never'}</td>
          <td style="padding:8px">
            <div style="display:flex;gap:4px">
              <button class="btn btn-ghost btn-sm" onclick="dwTestSite('${esc(s.id)}')">🧪</button>
              ${s.editable?`
                <button class="btn btn-ghost btn-sm" onclick="dwEditSite(${s.id},'${esc(s.group_name)}','${esc(s.url)}')">✏</button>
                <button class="btn btn-danger btn-sm" onclick="dwDeleteSite(${s.id},'${esc(s.group_name)}')">✕</button>
              `:''}
            </div>
          </td>
        </tr>`;

  const renderTable = (sites, showStatus=false) => {
    if(!sites.length) return '<div class="empty" style="padding:10px"><div class="empty-txt">No sites in this category</div></div>';
    const hasStat = showStatus;
    return `<table style="width:100%;border-collapse:collapse;font-size:11px">
      <thead><tr>
        ${hasStat?'<th style="padding:6px 8px;border-bottom:1px solid var(--border);text-align:left;font-size:9px;color:var(--muted);text-transform:uppercase">Status</th>':''}
        <th style="padding:6px 8px;border-bottom:1px solid var(--border);text-align:left;font-size:9px;color:var(--muted);text-transform:uppercase">Group</th>
        <th style="padding:6px 8px;border-bottom:1px solid var(--border);text-align:left;font-size:9px;color:var(--muted);text-transform:uppercase">.onion URL</th>
        <th style="padding:6px 8px;border-bottom:1px solid var(--border);text-align:left;font-size:9px;color:var(--muted);text-transform:uppercase">Last Checked</th>
        <th style="padding:6px 8px;border-bottom:1px solid var(--border);text-align:left;font-size:9px;color:var(--muted);text-transform:uppercase">Actions</th>
      </tr></thead>
      <tbody>` +
      sites.map(s => {
        return `<tr style="border-bottom:1px solid rgba(33,38,45,.4)">
          ${hasStat?`<td style="padding:8px">${statusBadge(s)}</td>`:''}
          <td style="padding:8px"><span class="gtag">${esc(s.group_name)}</span>${!s.editable?'<span style="font-size:8px;color:var(--muted);margin-left:4px">default</span>':''}</td>
          <td style="padding:8px"><span class="mono" style="font-size:9px;color:var(--txt2);word-break:break-all">${esc(s.url)}</span></td>
          <td style="padding:8px;font-size:10px;color:var(--muted)">${s.last_checked?fts(s.last_checked):'Never'}</td>
          <td style="padding:8px">
            <div style="display:flex;gap:4px;flex-wrap:wrap">
              ${String(s.last_status)!=='200'?`<button class="btn btn-sm" style="background:rgba(63,185,80,.15);border:1px solid rgba(63,185,80,.3);color:var(--green);font-size:9px" onclick="dwMarkActive('${esc(s.id)}','${esc(s.group_name)}')" title="Manually confirm this site is active">✓ Active</button>`:''}
              <button class="btn btn-ghost btn-sm" onclick="dwTestSite('${esc(s.id)}')" title="Test via Tor">🧪</button>
              ${s.editable?`
                <button class="btn btn-ghost btn-sm" onclick="dwEditSite(${s.id},'${esc(s.group_name)}','${esc(s.url)}')">✏</button>
                <button class="btn btn-danger btn-sm" onclick="dwDeleteSite(${s.id},'${esc(s.group_name)}')">✕</button>
              `:''}
            </div>
          </td>
        </tr>`;
      }).join('') +
      '</tbody></table>';
  };

  c.innerHTML = `
    <div style="margin-bottom:15px">
      <div style="font-size:10px;font-weight:700;color:var(--green);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">✅ Confirmed Active .onion Sites (HTTP 200)</div>
      ${renderTable(active)}
    </div>
    <div style="margin-bottom:15px">
      <div style="font-size:10px;font-weight:700;color:var(--cyan);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">◎ Configured / Pending Test</div>
      ${renderTable(pending)}
    </div>
    <div style="margin-bottom:15px;border:1px solid rgba(188,140,255,.2);border-radius:var(--r);padding:10px;background:rgba(188,140,255,.04)">
      <div style="font-size:10px;font-weight:700;color:var(--purple);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">🔍 Newly Discovered from Intelligence Feeds</div>
      <div style="font-size:9px;color:var(--muted);margin-bottom:8px">These .onion sites were automatically extracted from ransomware victim data. Confirmed-active sites are shown first.</div>
      ${discoveredActive.length ? `
        <div style="font-size:9px;font-weight:700;color:var(--green);margin-bottom:5px">● CONFIRMED ACTIVE (${discoveredActive.length})</div>
        <div style="max-height:200px;overflow-y:auto;margin-bottom:10px">${renderTable(discoveredActive, true)}</div>
      ` : ''}
      <div style="font-size:9px;font-weight:700;color:var(--muted);margin-bottom:5px">◌ UNVERIFIED / PENDING CHECK (${discoveredNew.length})</div>
      <div style="max-height:250px;overflow-y:auto">${renderTable(discoveredNew, true)}</div>
    </div>
    <div>
      <div style="font-size:10px;font-weight:700;color:var(--red);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">✗ Offline / Error Sites</div>
      ${renderTable(offline)}
    </div>
  `;
}

async function dwAddSite(){
  const group = document.getElementById('dw-new-group').value.trim();
  const url   = document.getElementById('dw-new-url').value.trim();
  const desc  = document.getElementById('dw-new-desc').value.trim();
  if(!group){toast('Enter group/threat actor name','err');return;}
  if(!url||!url.includes('.onion')){toast('Enter a valid .onion URL','err');return;}

  const btn = document.getElementById('dw-add-btn');
  if(btn){ btn.disabled=true; btn.textContent='Adding...'; }

  const data = await api('/api/darkweb/sites',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({group_name:group,url,description:desc,active:true})});

  if(btn){ btn.disabled=false; btn.textContent='+ Add'; }

  // Accept both 'added' (new) and 'updated' (already existed, now claimed)
  if(data?.status==='added' || data?.status==='updated' || data?.id){
    const msg = data?.status==='updated'
      ? `Updated: ${group} (URL was already in monitoring queue)`
      : `Added: ${group} — queued for verification`;
    toast(msg,'ok');
    document.getElementById('dw-new-group').value='';
    document.getElementById('dw-new-url').value='';
    document.getElementById('dw-new-desc').value='';
    await loadDWSites();
    // Auto-trigger a test of the newly added site
    if(data?.id) setTimeout(()=>dwTestSite(data.id), 500);
  }
}

async function dwTestSite(siteId){
  toast('Testing '+siteId+'...','info');
  const data = await api('/api/darkweb/sites/'+siteId+'/test',{method:'POST'});
  if(!data) return;
  const msg = data.status==='reachable'
    ? `✓ ${data.group_name}: Online (${data.latency_ms}ms)`
    : `✗ ${data.group_name}: ${data.status} — ${data.message||data.error||'timeout'}`;
  toast(msg, data.status==='reachable'?'ok':'err');
  setTimeout(loadDWSites, 1000);
}

function dwEditSite(id, currentGroup, currentUrl){
  const newUrl = prompt(`Update .onion URL for ${currentGroup}:`, currentUrl);
  if(!newUrl || newUrl===currentUrl) return;
  if(!newUrl.includes('.onion')){toast('Must be .onion URL','err');return;}
  api('/api/darkweb/sites/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:newUrl})})
    .then(d=>{
      if(d?.status==='updated'){toast('URL updated','ok');loadDWSites();}
    });
}

async function dwDeleteSite(id, group){
  if(!confirm(`Delete ${group} from monitoring?`)) return;
  const data = await api('/api/darkweb/sites/'+id,{method:'DELETE'});
  if(data?.status==='deleted'){toast(`Deleted: ${group}`,'ok');loadDWSites();}
}

async function dwMarkActive(siteId, group){
  const data = await api('/api/darkweb/sites/'+siteId+'/mark-active',{method:'POST'});
  if(data?.status==='marked_active'){
    toast(`Marked ACTIVE: ${group}`, 'ok');
    setTimeout(loadDWSites, 500);
  }
}

async function dwTriggerScan(){
  const data = await api('/api/darkweb/scan/now',{method:'POST'});
  toast(data?.message||'Scan triggered','ok');
}

async function loadDWResults(){
  const data = await api('/api/darkweb/results?page_size=20');
  const tb = document.getElementById('dw-results-body');
  const items = data?.items||[];
  if(!items.length){
    tb.innerHTML='<tr><td colspan="5" class="lrow" style="color:var(--muted)">No dark web discoveries yet — enable Tor and set ENABLE_DARKWEB=true</td></tr>';
    return;
  }
  tb.innerHTML = items.map(v=>`<tr class="clickable" onclick="openVictimModal(${v.id})">
    <td style="font-weight:600;max-width:160px" class="trunc">${esc(v.victim_name)}</td>
    <td><span class="gtag">${esc(v.group_name)}</span></td>
    <td style="font-size:10px">${esc(v.country||'—')}</td>
    <td style="font-size:10px;color:var(--muted)">${fdt(v.discovery_date)}</td>
    <td style="font-size:10px;color:var(--txt2)">${esc(v.data_size||'—')}</td>
  </tr>`).join('');
}

// ── Live Threat Feed ─────────────────────────────────────────────────────────
const CATEGORY_COLORS = {
  ransomware:'var(--red)', apt:'var(--purple)', malware:'var(--orange)',
  vulnerability:'var(--yellow)', credential:'var(--cyan)', news:'var(--blue)',
  research:'var(--green)', alerts:'var(--red)', community:'var(--txt2)', general:'var(--muted)'
};
const CATEGORY_ICONS = {
  ransomware:'☠', apt:'🎯', malware:'⚙', vulnerability:'🔓',
  credential:'🔑', news:'📰', research:'🔬', alerts:'⚡', general:'•'
};

async function loadFeed(){
  const cat   = document.getElementById('feed-cat')?.value || '';
  const hours = document.getElementById('feed-hours')?.value || '24';
  const c = document.getElementById('feed-items-container');
  c.innerHTML = '<div class="lrow"><span class="spinner"></span></div>';

  // Load stats
  const stats = await api('/api/feed/stats');
  if(stats){
    const sr = document.getElementById('feed-stats-row');
    sr.innerHTML = [
      ['Total Items', fmt(stats.total_items), 'c-cyan'],
      ['Last Hour', fmt(stats.last_hour), 'c-green'],
      ['Last 5 min', fmt(stats.last_5min), 'c-purple'],
      ['Categories', '6', 'c-yellow'],
    ].map(([label,val,cls])=>`<div class="stat-card ${cls}" style="padding:10px">
      <div class="stat-label">${label}</div>
      <div class="stat-val" style="font-size:18px">${val}</div>
    </div>`).join('');
    document.getElementById('feed-badge').textContent = stats.last_hour||0;
  }

  // Load feed items
  const params = new URLSearchParams({limit:60, hours, min_relevance:0.3});
  if(cat) params.set('category', cat);
  const data = await api('/api/feed/latest?' + params);
  const items = data?.items || [];

  if(!items.length){
    c.innerHTML = '<div class="empty" style="padding:40px"><div class="empty-ico">📡</div><div class="empty-txt">No feed items yet</div><div class="empty-sub">The web intel connector runs every 5 minutes and fetches from security blogs, Google News, and Reddit</div></div>';
    return;
  }

  c.innerHTML = items.map(item => renderFeedItem(item)).join('');
}

async function searchFeed(){
  const q = document.getElementById('feed-search')?.value?.trim();
  if(!q || q.length < 2) { loadFeed(); return; }
  const c = document.getElementById('feed-items-container');
  c.innerHTML = '<div class="lrow"><span class="spinner"></span></div>';
  const data = await api('/api/feed/search?q='+encodeURIComponent(q));
  const items = data?.items || [];
  if(!items.length){
    c.innerHTML = `<div class="empty" style="padding:30px"><div class="empty-txt">No results for "${esc(q)}"</div></div>`;
    return;
  }
  c.innerHTML = `<div style="font-size:11px;color:var(--muted);margin-bottom:10px">${items.length} results for "${esc(q)}"</div>`
    + items.map(renderFeedItem).join('');
}

function renderFeedItem(item){
  const cat      = item.category || 'general';
  const color    = CATEGORY_COLORS[cat] || 'var(--muted)';
  const icon     = CATEGORY_ICONS[cat]  || '•';
  const entities = (item.entities || []).slice(0,5);
  const relPct   = Math.round((item.relevance || 0) * 100);
  const relColor = item.relevance>=0.7?'var(--red)':item.relevance>=0.5?'var(--orange)':'var(--muted)';
  const pub      = (item.published || item.fetched_at || '').slice(0,16).replace('T',' ');

  return `<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r);
    padding:12px 14px;margin-bottom:8px;transition:border-color 0.15s;cursor:pointer;
    border-left:3px solid ${color}"
    onclick="window.open('${esc(item.url)}','_blank')"
    onmouseenter="this.style.borderColor='${color}'"
    onmouseleave="this.style.borderColor='var(--border)'">

    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px">
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:5px;flex-wrap:wrap">
          <span style="background:rgba(255,255,255,0.06);color:${color};font-size:10px;
            font-weight:700;padding:2px 8px;border-radius:4px;text-transform:uppercase">${icon} ${esc(cat)}</span>
          <span style="font-size:10px;color:var(--muted)">${esc(item.source)}</span>
          <span style="font-size:10px;color:var(--muted)">·</span>
          <span style="font-size:10px;color:var(--cyan);font-weight:600" title="Actual publication date from source">${item.published ? 'Published: '+item.published.slice(0,16).replace('T',' ') : pub} UTC</span>
          <span style="font-size:10px;color:${relColor};margin-left:auto">
            relevance: ${relPct}%
          </span>
        </div>
        <div style="font-size:13px;font-weight:600;color:var(--txt);margin-bottom:5px;
          line-height:1.4">${esc(item.title)}</div>
        ${item.summary?`<div style="font-size:11px;color:var(--txt2);line-height:1.6">${esc(item.summary.slice(0,200))}${item.summary.length>200?'…':''}</div>`:''}
        ${entities.length?`<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px">
          ${entities.map(e=>`<span class="badge bc" style="font-size:9px">${esc(e)}</span>`).join('')}
        </div>`:''}
      </div>
      <div style="display:flex;flex-direction:column;gap:4px;flex-shrink:0">
        <button class="btn btn-ai btn-sm" onclick="event.stopPropagation();askAIAboutFeedItem(${JSON.stringify(item.title).replace(/'/g,'&#39;')},${JSON.stringify(item.summary||'').replace(/'/g,'&#39;')})"
          style="white-space:nowrap">⬡ Ask AI</button>
        <a href="${esc(item.url)}" target="_blank" class="btn btn-ghost btn-sm"
          onclick="event.stopPropagation()" style="white-space:nowrap;text-decoration:none">
          ↗ Read
        </a>
      </div>
    </div>
  </div>`;
}

function askAIAboutFeedItem(title, summary){
  // Switch to AI chat tab and pre-fill with context
  nav('chat', document.querySelector('[data-view=chat]'));
  setTimeout(()=>{
    const inp = document.getElementById('chat-in');
    if(inp){
      inp.value = `Analyze this threat intelligence item and provide detailed context:

Title: ${title}

Summary: ${summary}

Who are the threat actors involved? What malware/TTPs are referenced? What are the defensive implications?`;
      inp.focus();
    }
  }, 200);
}


// ── Company Advisories ────────────────────────────────────────────────────────
let currentAdvId = null;

// The 25 monitored companies (must match advisory_monitor connector)
const TOP25_COMPANIES = [
  'Microsoft','Google','Apple','Amazon','Meta','Cloudflare','Cisco','Palo Alto Networks',
  'CrowdStrike','Fortinet','Check Point','SentinelOne','Zscaler','Okta','Splunk',
  'IBM','Oracle','SAP','Salesforce','ServiceNow','VMware','Broadcom','Qualys',
  'Tenable','Rapid7'
];

async function loadAdvisories(){
  const company  = document.getElementById('ca-company')?.value||'';
  const severity = document.getElementById('ca-sev')?.value||'';
  const atype    = document.getElementById('ca-adv-type')?.value||'';
  const hours    = document.getElementById('ca-hours')?.value||'720';
  const search   = document.getElementById('ca-search')?.value||'';

  const c = document.getElementById('ca-list-container');
  if(c) c.innerHTML = '<div class="lrow"><span class="spinner"></span></div>';

  // Load stats
  const stats = await api('/api/advisory/stats');
  if(stats){
    const sr = document.getElementById('ca-stats-row');
    const totalAdv = (stats.by_severity||[]).reduce((s,x)=>s+x.cnt,0);
    const critCount = (stats.by_severity||[]).find(x=>x.severity==='critical')?.cnt||0;
    const highCount = (stats.by_severity||[]).find(x=>x.severity==='high')?.cnt||0;
    if(sr) sr.innerHTML = [
      ['Total Advisories', totalAdv, 'c-cyan'],
      ['Critical', critCount, 'c-red'],
      ['High', highCount, 'c-orange'],
      ['Today', stats.today||0, 'c-purple'],
    ].map(([label,val,cls])=>`<div class="stat-card ${cls}" style="padding:10px">
      <div class="stat-label">${label}</div>
      <div class="stat-val" style="font-size:18px">${val}</div>
    </div>`).join('');
    document.getElementById('adv-badge').textContent = critCount||'';
  }

  const params = new URLSearchParams({hours, page_size:100});
  if(company) params.set('company',company);
  if(severity) params.set('severity',severity);
  if(atype)    params.set('advisory_type',atype);
  if(search)   params.set('search',search);

  const data = await api('/api/advisory/?'+params);
  const items = data?.items||[];
  const countEl = document.getElementById('ca-count');
  if(countEl) countEl.textContent = fmt(data?.total||0)+' advisories';

  if(!c) return;
  if(!items.length){
    c.innerHTML='<div class="empty" style="padding:40px"><div class="empty-ico">🏢</div><div class="empty-txt">No advisories found</div><div class="empty-sub">Advisory monitor fetches from Top 25 companies every 30 minutes.<br>Click "Refresh" or "Fetch All Feeds" to load now.</div></div>';
    loadCompany25Incidents();
    return;
  }

  c.innerHTML = items.map(adv => renderAdvCard(adv)).join('');
  loadCompany25Incidents();
}

function renderAdvCard(adv){
  const sevColors = {critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--green)'};
  const color = sevColors[adv.severity]||'var(--muted)';
  const cves  = adv.cves||[];
  return `<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r);
    padding:10px 12px;margin-bottom:7px;cursor:pointer;border-left:3px solid ${color};
    transition:border-color 0.15s"
    onclick="showAdvisoryDetail(${JSON.stringify(adv).replace(/'/g,'&#39;')})"
    onmouseenter="this.style.borderLeftColor='${color}'" >
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px">
      <div style="flex:1;min-width:0">
        <div style="display:flex;align-items:center;gap:5px;margin-bottom:4px;flex-wrap:wrap">
          <span class="badge ${adv.severity==='critical'?'bc':adv.severity==='high'?'bc':adv.severity==='medium'?'bm':'bh'}"
            style="font-size:9px">${adv.severity.toUpperCase()}</span>
          <span style="font-size:10px;color:var(--cyan);font-weight:600">${esc(adv.company)}</span>
          <span style="font-size:9px;color:var(--muted)">${adv.advisory_type==='official'?'🏛 Official':'🌐 External'} ${esc(adv.source_name||adv.advisory_type)}</span>
          <span style="font-size:9px;color:var(--muted)">· ${fdt(adv.published||adv.fetched_at)}</span>
        </div>
        <div style="font-size:12px;font-weight:600;color:var(--txt);line-height:1.4">${esc(adv.title)}</div>
        ${cves.length?`<div style="margin-top:4px">${cves.slice(0,4).map(c=>`<span class="badge b-cve" style="margin:1px;font-size:8px">${esc(c)}</span>`).join('')}</div>`:''}
      </div>
      <button class="btn btn-ai btn-sm" onclick="event.stopPropagation();analyzeAdvisory(${adv.id})"
        style="flex-shrink:0">⬡</button>
    </div>
  </div>`;
}

async function loadCompany25Incidents(){
  const c = document.getElementById('ca-company25-list');
  const badge = document.getElementById('ca-company25-badge');
  if(!c) return;
  c.innerHTML = '<div class="lrow"><span class="spinner"></span></div>';

  // Fetch last 30 days, all, large page to get the 25-company specific data
  const data = await api('/api/advisory/?hours=720&page_size=200');
  const all = data?.items||[];

  // Group by company, only keep TOP25
  const byCompany = {};
  all.forEach(adv => {
    const co = adv.company;
    if(!co) return;
    const isTop25 = TOP25_COMPANIES.some(t => co.toLowerCase().includes(t.toLowerCase()) || t.toLowerCase().includes(co.toLowerCase()));
    if(!isTop25) return;
    if(!byCompany[co]) byCompany[co] = [];
    byCompany[co].push(adv);
  });

  const companies = Object.keys(byCompany);
  if(badge) badge.textContent = companies.length + ' companies with alerts';

  if(!companies.length){
    c.innerHTML = '<div class="empty" style="padding:20px"><div class="empty-ico">🏢</div><div class="empty-txt">No incidents for Top 25 companies yet</div><div class="empty-sub">Click "Fetch All Feeds" to load advisories from official and external sources.</div></div>';
    return;
  }

  // Sort companies: most critical first
  companies.sort((a,b) => {
    const aCrit = byCompany[a].filter(x=>x.severity==='critical').length;
    const bCrit = byCompany[b].filter(x=>x.severity==='critical').length;
    return bCrit - aCrit || byCompany[b].length - byCompany[a].length;
  });

  const sevColors = {critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--green)'};
  c.innerHTML = companies.map(co => {
    const advs = byCompany[co].slice(0,5); // max 5 per company
    const hasCrit = advs.some(a=>a.severity==='critical');
    const hasHigh = advs.some(a=>a.severity==='high');
    const topColor = hasCrit?'var(--red)':hasHigh?'var(--orange)':'var(--yellow)';
    const official = advs.filter(a=>a.advisory_type==='official');
    const external = advs.filter(a=>a.advisory_type!=='official');
    return `<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--r);
      padding:12px;margin-bottom:10px;border-left:3px solid ${topColor}">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
        <span style="font-size:13px;font-weight:700;color:var(--txt)">${esc(co)}</span>
        ${hasCrit?'<span class="badge bc" style="font-size:8px">CRITICAL</span>':hasHigh?'<span class="badge bc" style="font-size:8px">HIGH</span>':''}
        ${official.length?`<span style="font-size:9px;color:var(--green);background:rgba(63,185,80,.1);padding:1px 6px;border-radius:4px;border:1px solid rgba(63,185,80,.2)">🏛 ${official.length} official</span>`:''}
        ${external.length?`<span style="font-size:9px;color:var(--cyan);background:rgba(0,212,255,.08);padding:1px 6px;border-radius:4px;border:1px solid rgba(0,212,255,.15)">🌐 ${external.length} external</span>`:''}
      </div>
      ${advs.map(adv => `<div style="display:flex;align-items:flex-start;gap:7px;padding:6px 0;
        border-bottom:1px solid rgba(33,38,45,.5);cursor:pointer"
        onclick="showAdvisoryDetail(${JSON.stringify(adv).replace(/'/g,'&#39;')})">
        <span class="badge ${adv.severity==='critical'?'bc':adv.severity==='high'?'bc':adv.severity==='medium'?'bm':'bh'}" style="font-size:8px;flex-shrink:0;margin-top:1px">${adv.severity.slice(0,4).toUpperCase()}</span>
        <div style="flex:1;min-width:0">
          <div style="font-size:11px;font-weight:600;color:var(--txt);line-height:1.4">${esc(adv.title)}</div>
          <div style="font-size:9px;color:var(--muted);margin-top:2px">
            ${adv.advisory_type==='official'?'🏛 Official':'🌐 External'} · ${esc(adv.source_name||adv.advisory_type)} · ${fdt(adv.published||adv.fetched_at)}
            ${adv.url?` · <a href="${esc(adv.url)}" target="_blank" style="color:var(--blue);text-decoration:none" onclick="event.stopPropagation()">↗ Source</a>`:''}
          </div>
          ${(adv.cves||[]).slice(0,3).map(cv=>`<span class="badge b-cve" style="margin:2px 1px 0;font-size:7px">${esc(cv)}</span>`).join('')}
        </div>
        <button class="btn btn-ai btn-sm" onclick="event.stopPropagation();showAdvisoryDetail(${JSON.stringify(adv).replace(/'/g,'&#39;')});analyzeAdvisory(${adv.id})" style="flex-shrink:0;padding:2px 7px">⬡</button>
      </div>`).join('')}
    </div>`;
  }).join('');
}

function showAdvisoryDetail(adv){
  currentAdvId = adv.id;
  const btn = document.getElementById('ca-analyze-btn');
  if(btn) btn.style.display = 'inline-flex';
  const iocs = adv.iocs||{};
  const cves = adv.cves||[];
  const ttps = adv.mitre_ttps||[];

  const detailEl = document.getElementById('ca-detail-body');
  if(!detailEl) return;
  detailEl.innerHTML = `
    <div style="margin-bottom:10px">
      <span class="badge ${adv.severity==='critical'?'bc':'bm'}" style="font-size:11px">${adv.severity.toUpperCase()}</span>
      <span style="color:var(--cyan);font-size:12px;font-weight:700;margin-left:8px">${esc(adv.company)}</span>
      <span style="font-size:10px;margin-left:6px;padding:1px 7px;border-radius:4px;${adv.advisory_type==='official'?'background:rgba(63,185,80,.1);color:var(--green);border:1px solid rgba(63,185,80,.2)':'background:rgba(0,212,255,.08);color:var(--cyan);border:1px solid rgba(0,212,255,.15)'}">${adv.advisory_type==='official'?'🏛 Official Vendor':'🌐 External Intelligence'}</span>
    </div>
    ${dr('Title','<strong>'+esc(adv.title)+'</strong>')}
    ${dr('Source', adv.url ? `<a href="${esc(adv.url)}" target="_blank" style="color:var(--blue)">${esc(adv.source_name)} ↗</a>` : esc(adv.source_name))}
    ${dr('Published',fts(adv.published||adv.fetched_at))}
    ${dr('Category',adv.category||'advisory')}
    ${dr('CVEs',cves.length?cves.map(c=>`<span class="badge b-cve" style="margin:1px">${esc(c)}</span>`).join(' '):'none')}
    ${dr('MITRE TTPs',ttps.length?'<br>'+ttps.map(t=>`<span style="display:block;font-size:10px;color:var(--purple)">${esc(t)}</span>`).join(''):'none')}
    ${dr('Domains (IOC)',iocs.domains?.length?iocs.domains.join(', '):'none')}
    ${dr('IPs (IOC)',iocs.ips?.length?iocs.ips.join(', '):'none')}
    ${dr('Hashes (IOC)',iocs.hashes?.length?iocs.hashes.join('<br>'):'none')}
    <div style="margin-top:10px;padding:10px;background:var(--bg);border-radius:var(--r);font-size:11px;color:var(--txt2);line-height:1.7">${esc(adv.summary||'No summary')}</div>
    ${adv.url?`<a href="${esc(adv.url)}" target="_blank" class="btn btn-ghost btn-sm" style="margin-top:10px;text-decoration:none">↗ Open Advisory</a>`:''}
    ${adv.ai_analysis?`<div style="margin-top:12px"><div style="font-size:10px;font-weight:700;color:var(--purple);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">⬡ AI Analysis</div><div class="ai-output">${mdToHTML(adv.ai_analysis)}</div></div>`:''}
  `;
  // Scroll detail panel into view if mobile
  detailEl.scrollIntoView({behavior:'smooth',block:'nearest'});
}

async function analyzeAdvisory(advId){
  const body = document.getElementById('ca-detail-body');
  if(!body) return;
  const existingAnalysis = body.querySelector('.ai-output');
  if(existingAnalysis && existingAnalysis.textContent.trim()) return; // Already analyzed
  body.innerHTML += '<div class="ai-loading" id="adv-ai-loading"><span class="spinner"></span> Analyzing with AI...</div>';
  const data = await api(`/api/advisory/${advId}/analyze`, {method:'POST'});
  document.getElementById('adv-ai-loading')?.remove();
  if(data?.analysis){
    body.innerHTML += `<div style="margin-top:12px"><div style="font-size:10px;font-weight:700;color:var(--purple);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">⬡ AI Analysis</div><div class="ai-output">${mdToHTML(data.analysis)}</div></div>`;
  }
}

function analyzeCurrentAdvisory(){
  if(currentAdvId) analyzeAdvisory(currentAdvId);
}

async function refreshAdvisories(){
  toast('Refreshing advisories from Top 25 companies...','info');
  await api('/api/advisory/refresh',{method:'POST'});
  toast('Advisory fetch triggered — check back in 2 minutes','ok');
  setTimeout(loadAdvisories, 3000);
}

async function caRefresh(){
  toast('Triggering advisory refresh...','info');
  await api('/api/advisory/refresh',{method:'POST'});
  toast('Advisory refresh running in background','ok');
  setTimeout(loadAdvisories, 4000);
}

async function genCoreReport(){
  const section = document.getElementById('core-report-section');
  section.style.display = 'block';
  document.getElementById('core-report-content').innerHTML = '<div class="ai-loading"><span class="spinner"></span> Generating CyberXTron FinalFeed Core Threat Report...</div>';
  section.scrollIntoView({behavior:'smooth'});
  const data = await api('/api/advisory/core-threat-report');
  document.getElementById('core-report-content').innerHTML = data?.report ? mdToHTML(data.report) : '<div style="color:var(--yellow)">AI not configured or no data yet</div>';
}

// Init
loadDash();
loadAIStatus();
setInterval(()=>{if(curView==='dashboard')loadDash();},60000);
setInterval(()=>{if(curView==='logs'&&document.getElementById('auto-log')?.checked)loadLogs();},30000);
