/* CTI Digest – Chapter 7 front end. Replace `api` with fetch() calls to your backend. */
const rng=(s=>()=>(s=(s*16807)%2147483647)/2147483647)(7);
const pick=a=>a[Math.floor(rng()*a.length)];
const many=(a,n)=>[...a].sort(()=>rng()-.5).slice(0,n);
const SOURCES=["BleepingComputer","The Hacker News","Mandiant Blog","CrowdStrike Blog","Microsoft Security","CISA Advisories","Krebs on Security","SecurityWeek"];
const ACTORS=[["Lazarus Group","KP"],["APT29","RU"],["APT28","RU"],["APT41","CN"],["Sandworm","RU"],["FIN7","RU"],["Scattered Spider","US"],["LockBit","RU"],["Volt Typhoon","CN"],["MuddyWater","IR"],["Kimsuky","KP"],["Conti","RU"]];
const PRODUCTS=["Exchange Server","FortiOS","Ivanti Connect Secure","Citrix NetScaler","Apache Tomcat","Cisco IOS XE","PAN-OS","VMware ESXi","Confluence","MOVEit Transfer"];
const TAGS=["ransomware","phishing","zero-day","supply-chain","cloud","ics","identity","botnet","espionage","data-breach"];
const VERBS=["Exploits","Targets","Abuses","Weaponizes","Hits","Compromises"];
const OBJS=["critical flaw","remote access tools","backup servers","cloud tenants","VPN gateways","build pipelines"];
const VULNS=Array.from({length:40},(_,i)=>({cve_id:`CVE-2026-${10000+i*977}`,product:pick(PRODUCTS),cvss:+(4+rng()*6).toFixed(1),exploited:rng()<.35}));
const DB={articles:[],sources:SOURCES.map((n,i)=>({_id:"s"+i,name:n})),actors:ACTORS.map(([n,c],i)=>({_id:"a"+i,name:n,country:c})),vulns:VULNS};
for(let i=0;i<500;i++){
  DB.articles.push({_id:i+1,title:`${pick(VERBS)} ${pick(OBJS)} #${String(i+1).padStart(5,"0")}`,
    published:new Date(Date.now()-rng()*180*864e5),source_id:"s"+Math.floor(rng()*8),
    actor_ids:many(DB.actors,Math.floor(rng()*4)).map(a=>a._id),cve_ids:many(VULNS,Math.floor(rng()*4)).map(v=>v.cve_id),
    tags:many(TAGS,1+Math.floor(rng()*3)),blocks:2+Math.floor(rng()*8)});
}
/* "api": each call reports how many collections (round trips) it needed */
const localApi={
  search(q){q=q.toLowerCase();return DB.articles.filter(a=>!q||a.title.toLowerCase().includes(q)||a.tags.some(t=>t.includes(q))).sort((a,b)=>b.published-a.published)},
  article(id,mode){const a=DB.articles.find(x=>x._id==id);
    const src=DB.sources.find(s=>s._id==a.source_id),act=a.actor_ids.map(i=>DB.actors.find(x=>x._id==i)),cv=a.cve_ids.map(c=>DB.vulns.find(v=>v.cve_id==c));
    return mode=="ref"?{a,src,act,cv,trips:1+1+(act.length?1:0)+(cv.length?1:0)}:{a,src,act,cv,trips:1}}
};
const API="http://localhost:5000/api";
const api={
  src:"db",
  async search(q){try{const r=await fetch(`${API}/articles?q=${encodeURIComponent(q)}`);if(!r.ok)throw 0;const j=await r.json();if(!j.length&&!q)throw 0;api.src="db";return j}catch(e){api.src="demo";return localApi.search(q).slice(0,15)}},
  async get(path){if(DEMO)return null;try{const r=await fetch(`${API}${path}`);if(!r.ok)throw 0;return await r.json()}catch(e){return null}},
  async article(id,m){try{const r=await fetch(`${API}/articles/${id}?mode=${m}`);if(!r.ok)throw 0;return await r.json()}catch(e){return localApi.article(id,m)}}
};
const $=s=>document.querySelector(s),view=$("#view");
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let mode="embed";

const pages={
async articles(arg){
  const q=arg||"";const all=await api.search(q);const rows=all.slice(0,15);
  const st=api.src=="db"?await api.get("/model/stats"):null,total=(st&&(st.collections.find(c=>c.name=="articles")||{}).count)||DB.articles.length;
  view.innerHTML=`<h1>Articles</h1><p class="lead">Search the ${total.toLocaleString()} seeded threat reports. Open one to see how many reads it costs with embedding versus referencing.</p>
  <form class="row card" id="f"><input id="q" value="${esc(q)}" placeholder="Title or tag, e.g. ransomware" aria-label="Search"><button>Search</button></form>
  <p class="meta">showing ${rows.length} of ${total.toLocaleString()} articles (newest first)</p>
  ${api.src=="demo"?`<div class="card"><b>Showing demo data.</b> <span class="meta">The server is not reachable, or the database has no articles. Start MongoDB and server.py, then seed the database (Lab 7.1).</span> <button data-run="seed7" ${LAB.seed7.st=="running"||ROLE=="Client"?"disabled":""}>${LAB.seed7.st=="running"?"Seeding…":"Seed database"}</button>${LAB.seed7.st=="failed"?`<div class="log">${esc(LAB.seed7.log.join("\n"))}</div>`:""}</div>`:""}
  ${rows.map(a=>`<a class="card" style="display:block;color:inherit;text-decoration:none" href="#article/${a._id}"><b>${esc(a.title)}</b><div class="meta">${new Date(a.published).toDateString()} · ${a.blocks} content blocks</div>${a.tags.map(t=>`<span class="tag t-embed">${t}</span>`).join("")}${a.actor_ids.length?`<span class="tag t-ref">${a.actor_ids.length} actors</span>`:""}${a.cve_ids.length?`<span class="tag t-ref">${a.cve_ids.length} CVEs</span>`:""}</a>`).join("")}`;
  $("#f").onsubmit=e=>{e.preventDefault();location.hash="#articles/"+encodeURIComponent($("#q").value)};
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
},
article(id){
  const draw=async()=>{const r=await api.article(id,mode);
    view.innerHTML=`<p class="meta"><a href="#articles">Articles</a> / ${r.a._id}</p><h1>${esc(r.a.title)}</h1>
    <div class="row"><button class="alt ${mode=="embed"?"on":""}" data-m="embed">Embedded design</button><button class="alt ${mode=="ref"?"on":""}" data-m="ref">Referenced design</button></div>
    <div class="card ${mode}" style="margin-top:14px"><div class="stat">${r.trips} ${r.trips==1?"query":"queries"}</div>
    <p class="meta">${mode=="embed"?"Content blocks, tags and sectors live inside the article document, so one read returns the whole page.":"Article, source, actors and CVEs live in separate collections, so the page is assembled from several reads (or one $lookup)."}</p></div>
    <div class="split"><div class="card embed"><b>Embedded inside the article</b><p>${r.a.blocks} content blocks</p>${r.a.tags.map(t=>`<span class="tag t-embed">${t}</span>`).join("")}</div>
    <div class="card ref"><b>Referenced from other collections</b>
      <p class="meta">sources</p>${esc(r.src.name)}
      <p class="meta">threat_actors</p>${r.act.map(x=>`<span class="tag t-ref">${esc(x.name)} (${x.country})</span>`).join("")||"none"}
      <p class="meta">vulnerabilities</p>${r.cv.map(v=>`<span class="tag t-ref">${v.cve_id} · CVSS ${v.cvss}${v.exploited?" · exploited":""}</span>`).join("")||"none"}</div></div>`;
    view.querySelectorAll("[data-m]").forEach(b=>b.onclick=()=>{mode=b.dataset.m;draw()})};
  draw();
},
async model(){const h=location.hash;
  const [st,ac]=await Promise.all([api.get("/model/stats"),api.get("/model/actors")]);
  if(location.hash!==h)return;
  const live=!!(st&&ac),cols=live?st.collections:localStats(),act=live?ac:localActors();
  view.innerHTML=`<h1>Data model</h1><p class="lead">Rule of thumb from this lab: embed what is read together and bounded in size; reference what is shared, large or changes on its own.</p>
  <div class="grid">
  <div class="card embed"><b>Embedded in articles</b><pre>content_blocks: [ ... ]
tags: [ ... ]
sectors: [ ... ]</pre><p class="meta">Always shown with the article, small, never queried alone.</p></div>
  <div class="card ref"><b>Referenced</b><pre>source_id   → sources
actor_ids[] → threat_actors
cve_ids[]   → vulnerabilities.cve_id</pre><p class="meta">Shared by many articles; update once, correct everywhere.</p></div></div>
  <h2>Collections</h2><div class="card"><p class="meta">${live?`Read from MongoDB, database <code>${esc(st.db)}</code>.`:"Demo data: the server is not reachable, or Demo data is on."}</p>
  <table><tr><th>Collection</th><th>Documents</th><th>Average size</th><th>Index</th></tr>
  ${cols.map(c=>`<tr><td>${c.name}</td><td>${c.count.toLocaleString()}</td><td class="mono">${c.avg_obj?(c.avg_obj/1024).toFixed(1)+" KB":"–"}</td><td>${c.indexes.length?c.indexes.map(i=>`<code>${esc(i)}</code>`).join(", "):"_id"}</td></tr>`).join("")}</table></div>
  <h2>Activity 7.1: which actor is an actual threat?</h2>
  <div class="card"><p class="meta">Score = articles in the last ${act.days||90} days + 3 × articles tied to an exploited-in-the-wild CVE. Top quarter = high, upper half = medium, the rest = low. Embedding this verdict in every article makes "show the article and how dangerous its actors are" one read; changing a verdict then rewrites every article that embeds it.</p>
  <table><tr><th>Actor</th><th>Country</th><th>Score</th><th>Level</th><th>Actual threat?</th></tr>
  ${act.actors.map(x=>`<tr><td>${esc(x.name)}</td><td>${x.country}</td><td class="mono">${x.score}</td><td><span class="tag ${x.level=="high"?"t-ref":"t-embed"}">${x.level}</span></td><td>${x.actual?"<b>YES</b>":"no"}</td></tr>`).join("")}</table>
  <p class="meta">${act.actual} of ${act.actors.length} actors are classed as an actual threat.</p></div>
  <div class="grid">${lab7("seed7","Lab 7.1","Seed the CTI Digest database","Drops and recreates articles, sources, threat_actors and vulnerabilities in the chapter-07 database (500 articles, fixed random seed 7).")}
  ${lab7("a71","Activity 7.1","Embed threat actors inside articles","Builds articles_embedded and times four queries on both designs. The log holds the comparison tables and the written answers.")}</div>`;
  bind7();
},
async workingset(){const h=location.hash;
  const w=await api.get("/workingset");
  if(location.hash!==h)return;
  const gb=x=>(x/1073741824).toFixed(2)+" GB",mb=x=>(x/1048576).toFixed(1)+" MB";
  const kb=w&&w.avg_obj?w.avg_obj/1024:6; // KB per article: measured, or ~6 KB when offline
  if(w&&!WS.init){WS.init=true;WS.n=Math.max(500,Math.round(w.count/500)*500);WS.c=Math.max(1,Math.min(16,Math.round(w.cache_max/1073741824*2)))}
  const ws0=w?w.data+w.indexes:0,fit=w?Math.min(100,ws0/w.cache_max*100):0;
  view.innerHTML=`<h1>Working set</h1><p class="lead">The working set is the data and indexes your queries touch often. If it fits in the cache, reads come from memory. Move the sliders to see when it stops fitting.</p>
  ${w?`<div class="card"><b>Measured on this server</b><p class="meta">From db.collStats("articles") and db.serverStatus().wiredTiger.cache.</p>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">${stat("Articles",w.count.toLocaleString())}${stat("Average article",(w.avg_obj/1024).toFixed(1)+" KB")}${stat("Data",mb(w.data))}${stat("Indexes",mb(w.indexes))}${stat("Cache size",gb(w.cache_max))}${stat("In cache now",gb(w.in_cache))}</div>
  <div class="bar" style="margin-top:12px"><i style="width:${fit}%;background:${fit>=100?"var(--ref)":"var(--embed)"}"></i></div>
  <p class="meta">Data plus indexes of articles use ${fit.toFixed(2)} % of the cache. ${fit>=100?"They do not fit: expect disk reads.":"They fit comfortably."}${w.lab72?` Lab 7.2's docs_2kb holds ${w.lab72.count.toLocaleString()} documents (${mb(w.lab72.data)} data, ${mb(w.lab72.indexes)} indexes).`:""}</p></div>`:`<p class="meta">Demo data: the server is not reachable, or Demo data is on. The sliders use a 6 KB article.</p>`}
  <div class="card"><label>Articles <b id="nv"></b><input type="range" id="n" min="500" max="500000" step="500" value="${WS.n}" style="width:100%"></label>
  <label>Cache size (GB) <b id="cv"></b><input type="range" id="c" min="1" max="16" value="${WS.c}" style="width:100%"></label>
  <label>Share of articles read recently <b id="hv"></b><input type="range" id="h" min="1" max="100" value="${WS.h}" style="width:100%"></label>
  <div class="bar"><i id="bar"></i></div><div id="out"></div></div>
  ${lab7("l72","Lab 7.2","Working set analysis","Inserts 100,000 documents of about 2 KB into docs_2kb, reads the WiredTiger cache, then runs random reads and watches the hit ratio. It can take a few minutes.")}`;
  const go=()=>{const n=+$("#n").value,c=+$("#c").value,hh=+$("#h").value,sh=hh/100;Object.assign(WS,{n,c,h:hh});
    const data=n*sh*kb/1048576,idx=n*0.0001*2/1,wss=data+idx,pct=Math.min(100,wss/(c*.5)*100); // WiredTiger default cache ≈ 50%
    $("#nv").textContent=n.toLocaleString();$("#cv").textContent=c;$("#hv").textContent=hh+"%";
    $("#bar").style.width=pct+"%";$("#bar").style.background=pct>=100?"var(--ref)":"var(--embed)";
    $("#out").innerHTML=`<div class="stat">${wss.toFixed(2)} GB</div><p>${pct>=100?"Working set is larger than the cache. Expect disk reads and slower queries.":"Working set fits in the cache."} Usable cache ≈ ${(c*.5).toFixed(1)} GB.</p>`};
  view.querySelectorAll("input[type=range]").forEach(i=>i.oninput=go);go();bind7();
},
async metrics(){clearInterval(window._t);
  let left=10,m=await getMetrics();
  if(location.hash!="#metrics")return;
  const g=x=>(x/1073741824).toFixed(2),tile=(v,l)=>`<div class="card"><div class="stat">${v}</div>${l}</div>`;
  const draw=()=>{const hit=m.hit!=null?m.hit:m.since_start,hist=m.history.length?m.history:(hit!=null?[hit]:[]),mx=Math.max(1,...m.by_source.map(x=>x.n));
    view.innerHTML=`<h1>Database metrics</h1><p class="lead">How well MongoDB's memory cache serves this site, read every 10 seconds. The hit ratio is the share of page requests answered from memory instead of disk.${m.live?"":" (Demo data: simulated numbers; the server is not reachable or Demo data is on.)"}</p>
    <p class="meta mono" id="next">● ${m.live?"Live":"Simulated"} · next read in ${left}s</p>
    <div class="split"><div class="card"><div class="row" style="justify-content:space-between"><b>Cache hit ratio</b><span class="stat">${hit!=null?hit.toFixed(1)+"%":"–"}</span></div>
      <div style="display:flex;align-items:flex-end;gap:3px;height:140px;margin-top:10px;border-bottom:1px solid rgba(128,128,128,.35)">${hist.map(v=>`<i title="${v}%" style="flex:1;display:block;min-width:4px;border-radius:3px 3px 0 0;background:var(--acc);height:${Math.max(2,(Math.max(95,v)-95)/5*100)}%"></i>`).join("")}</div>
      <div class="row meta" style="justify-content:space-between"><span>first read</span><span>now</span></div><p class="meta">The axis runs from 95 % to 100 %.</p></div>
    <div class="card"><b>Cache used</b><div style="position:relative;width:170px;height:170px;margin:14px auto">
      <div style="position:absolute;inset:0;border-radius:50%;background:conic-gradient(var(--acc) ${m.fill*3.6}deg,rgba(128,128,128,.25) 0);-webkit-mask:radial-gradient(farthest-side,transparent 66%,#000 67%);mask:radial-gradient(farthest-side,transparent 66%,#000 67%)"></div>
      <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center"><div class="stat">${Math.round(m.fill)}%</div><span class="meta">${g(m.in_cache)} GB of ${g(m.max)} GB</span></div></div></div></div>
    <div class="grid">${tile(m.since_start!=null?m.since_start.toFixed(2)+"%":"–","hit ratio since start")}${tile(m.fill.toFixed(2)+"%","cache fill")}${tile(m.requests.toLocaleString(),"page requests (10 s)")}${tile(m.disk_reads.toLocaleString(),"disk reads (10 s)")}</div>
    <h2>What is stored</h2><div class="grid">${[["articles","articles"],["sources","sources"],["threat_actors","threat actors"],["vulnerabilities","vulnerabilities"]].map(([k,l])=>tile((m.counts[k]||0).toLocaleString(),l)).join("")}</div>
    <h2>Articles by source</h2><div class="card">${m.by_source.map(x=>`<div class="bars" style="grid-template-columns:170px 1fr 56px"><span>${esc(x.name||"unknown")}</span><div class="bar"><i style="width:${x.n/mx*100}%;background:var(--embed)"></i></div><span class="mono">${x.n}</span></div>`).join("")||'<p class="meta">No articles yet.</p>'}</div>
    ${lab7("a72","Activity 7.2","Monitor the cache hit ratio","Runs lab7_2tryityourself.py for 3 cycles of 5 seconds: reads the report list from GitHub, stores the new reports and prints the interval hit ratio. Needs internet access.")}
    <p class="meta">Real data: db.serverStatus().wiredTiger.cache, "pages requested from the cache" against "pages read into cache", as the change between two reads.</p>`;
    bind7()};
  draw();
  window._t=setInterval(async()=>{if(location.hash!="#metrics")return;left--;
    if(left<=0){left=10;const n=await getMetrics();if(location.hash!="#metrics")return;m=n;draw()}
    else{const e=$("#next");if(e)e.textContent=`● ${m.live?"Live":"Simulated"} · next read in ${left}s`}},1000);
},
tour(){
  view.innerHTML=`<h1>Course tour</h1><p class="lead">What each chapter adds to the platform and where to see it.</p>
  <div class="grid">${[["Embedding vs referencing","Articles and Data model pages","#model"],["Reading an article","Compare query counts per design","#articles"],["Working set and cache","Size the cache against your data","#workingset"],["Cache hit ratio","Live-style metrics page","#metrics"],["08 Replica sets","Deploy rs0, add an arbiter, force failover, set priorities","#replica"],["09 CAP theorem","Write concern latency, journaling and a network partition","#cap"],["10 Transactions","Bank transfer, retry with backoff, inventory reservation","#tx"],["11 Sharding","Shard key choices, live resharding, hotspots","#shard"],["12 Security","Roles and RBAC, redaction with a view, TLS","#sec"],["13 Containers and the cloud","Keyfile replica set, exporter, Kubernetes StatefulSet","#cloud"],["13 Operations","Deployment, failover test and monitoring charts","#ops"],["14 Monitoring and backup","Metrics, webhook alerts, backups with verified restore","#mon"],["14 Moderation alerts","Acknowledge the monitor's warnings","#mod/alerts"],["15 Multi-tenant cases","Tenant isolation, roles and a rate limit, and moving a tenant to its own collection","#tenants"],["15 Cases","Your organisation's cases, and only yours","#cases"],["15 Organisations","Tenants, members and cases per organisation","#ops/orgs"],["16 Cassandra and Neo4j","One model in three databases, a hybrid architecture, a fraud query service","#hybrid"],["16 Audit log","Every action kept in Cassandra: one partition per day, newest first","#ops/audit"],["16 Fraud review","MongoDB, Cassandra and Neo4j behind circuit breakers","#mod/fraud"],["17 Vector search and RAG","Chunks, $vectorSearch, cited answers with memory; HNSW against IVF","#rag"],["17 Ask CTI Verify","Questions answered from the annual reports, with citations","#ask"],["17 Ask index","The vector index behind Ask","#ops/ask"],["18 Comparative capstone","Three databases compared on the same threats; false-positive detection","#capstone"],["18 False-positive review","Indicators that should probably not be blocked","#mod/fp"],["18 Source reliability","Which feeds produce false positives or copy each other","#ops/sources"]].map(([t,d,h])=>`<a class="card" style="color:inherit;text-decoration:none" href="${h}"><b>${t}</b><p class="meta">${d}</p></a>`).join("")}</div>`;
}};

/* ===== Chapter 8: replica set (simulated). Real backend contract:
   GET  /api/replica/status      -> {members:[{name,state,priority,votes,docs}]}
   POST /api/replica/run/{lab}   -> runs lab8_1 / lab8_1_arbiter / lab8_2 / lab8_2_priority, returns result + log
   Browsers can't run docker or pymongo, so a small Flask API should call the lab scripts. ===== */
let DEMO=false; // true = always use the simulated results
let ROLE="Administrator"; // Administrator and Moderator can run course labs; Client cannot (as on the Users and roles page)
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const COL={mongo1:"var(--m1)",mongo2:"var(--m2)",mongo3:"var(--m3)"};
const RS={arb:false,m:[{n:"mongo1",role:"PRIMARY",prio:3,docs:0},{n:"mongo2",role:"SECONDARY",prio:2,docs:0},{n:"mongo3",role:"SECONDARY",prio:1,docs:0}]};
const LAB={l81:{},a81:{},l82:{},a82:{},seed7:{},a71:{},l72:{},a72:{}};
Object.values(LAB).forEach(l=>Object.assign(l,{st:"idle",log:[],d:null,open:false}));
/* ===== Chapter 7 helpers: lab panel, demo fallbacks and the live metrics read ===== */
const WS={n:50000,c:4,h:20,init:false}; // Working set slider values survive a redraw
const MH=[];                            // simulated hit-ratio history, used only when the server is not reachable
const bind7=()=>{view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()})};
const lab7=(k,kind,title,desc)=>{const l=LAB[k];
  return `<article class="card lab"><div class="row" style="justify-content:space-between"><span class="kind mono">${kind}</span><span class="badge ${l.st}">${l.st=="idle"?"Not run":l.st=="running"?"Running":l.st=="passed"?"Passed":"Failed"}</span></div>
  <div class="meta">${title}</div><p>${desc}</p>
  <div class="foot"><span class="meta">${l.at?"Your run at "+l.at:"No result yet"}</span><span class="row"><button class="alt" data-log="${k}">${l.open?"Hide":"Show"} log</button><button data-run="${k}" ${l.st=="running"||ROLE=="Client"?"disabled":""} ${ROLE=="Client"?'title="Clients cannot run course labs"':""}>${l.st=="running"?"Running…":"Run"}</button></span></div>
  ${l.open?`<div class="log">${esc(l.log.join("\n")||(l.st=="running"?"Running the real script. Its output appears here when it finishes.":"(no output)"))}</div>`:""}</article>`};
const localStats=()=>[["articles",DB.articles.length,"published, actor_ids"],["sources",DB.sources.length,""],["threat_actors",DB.actors.length,""],["vulnerabilities",DB.vulns.length,"cve_id (unique)"]]
  .map(([name,count,ix])=>({name,count,avg_obj:0,indexes:ix?ix.split(", "):[]}));
const localActors=()=>{const cut=Date.now()-90*864e5,ex=new Set(DB.vulns.filter(v=>v.exploited).map(v=>v.cve_id)),rec={},lnk={};
  DB.articles.forEach(a=>{const has=a.cve_ids.some(c=>ex.has(c));a.actor_ids.forEach(id=>{if(+a.published>=cut)rec[id]=(rec[id]||0)+1;if(has)lnk[id]=(lnk[id]||0)+1})});
  const sc=DB.actors.map(x=>({name:x.name,country:x.country,score:(rec[x._id]||0)+3*(lnk[x._id]||0)})),o=sc.map(x=>x.score).sort((a,b)=>a-b),
    med=o[Math.floor(o.length/2)],p75=o[Math.floor(o.length*3/4)];
  sc.forEach(x=>{x.level=x.score>=p75?"high":x.score>=med?"medium":"low";x.actual=x.level!="low"});
  sc.sort((a,b)=>b.score-a.score);return{actors:sc,actual:sc.filter(x=>x.actual).length,days:90}};
async function getMetrics(){const m=await api.get("/metrics");if(m&&!m.error)return m;
  const v=+(99+Math.random()).toFixed(2),used=53+Math.round(Math.random()*3);MH.push(v);if(MH.length>30)MH.shift();
  return{live:false,hit:v,since_start:99.45,fill:used,in_cache:used/100*4.5*1073741824,max:4.5*1073741824,requests:600+Math.floor(Math.random()*200),disk_reads:Math.floor(Math.random()*3),
    history:MH.slice(),counts:{articles:DB.articles.length,sources:DB.sources.length,threat_actors:DB.actors.length,vulnerabilities:DB.vulns.length},
    by_source:SOURCES.map((n,i)=>({name:n,n:DB.articles.filter(a=>a.source_id=="s"+i).length})).sort((a,b)=>b.n-a.n),next_in:10}}
const primary=()=>RS.m.find(x=>x.role=="PRIMARY");
const stamp=()=>new Date().toTimeString().slice(0,8);
const L=(k,t)=>{LAB[k].log.push(`[${stamp()}] ${t}`);redraw()};
const redraw=()=>{const [p,a0]=location.hash.slice(1).split("/");if(p==""||p=="articles")return pages.articles(a0&&decodeURIComponent(a0));if(p=="model"||p=="workingset"||p=="metrics"||p=="replica"||p=="cap"||p=="tx"||p=="shard"||p=="sec"||p=="cloud"||p=="ops"||p=="mon"||p=="mod"||p=="hybrid"||p=="tenants"||p=="cases"||p=="rag"||p=="ask"||p=="capstone")pages[p]()};
const top100=()=>DB.articles.slice().sort((a,b)=>b.published-a.published).slice(0,100);
function stepDown(k){const old=primary(),cand=RS.m.filter(x=>x!==old).sort((a,b)=>b.prio-a.prio)[0];
  old.role="SECONDARY";cand.role="PRIMARY";return{old,cand}}
const runs={
async l81(){RS.m.forEach(x=>x.docs=0);L("l81","Starting 3 members of rs0 and running rs.initiate() ...");
  for(const m of RS.m){await sleep(500);m.docs=100;L("l81",`${m.n}: 100 of 100 articles copied`)}
  LAB.l81.d={sample:top100().slice(0,5).map(a=>a.title)}},
async a81(){L("a81","Starting arbiter container on port base+3 ...");await sleep(600);RS.arb=true;
  L("a81","rs.addArb() done: arbiter reports state ARBITER");
  LAB.a81.d={before:{v:3,maj:2,tol:1},after:{v:4,maj:3,tol:1}}},
async l82(){const old=primary();L("l82",`Reader started; primary is ${old.n}`);const reads=[];
  for(let i=1;i<=6;i++){reads.push(old.n);await sleep(150)}
  L("l82",`rs.stepDown() on ${old.n}; election starts`);const {cand}=stepDown();await sleep(700);
  L("l82",`NEW PRIMARY ${cand.n} elected`);
  for(let i=7;i<=14;i++){reads.push(cand.n);await sleep(100)}
  LAB.l82.d={old:old.n,nu:cand.n,reads,secs:(0.9+Math.random()*.4).toFixed(1)}},
async a82(){RS.m.forEach(x=>x.role="SECONDARY");RS.m.sort((a,b)=>b.prio-a.prio)[0].role="PRIMARY";RS.m.sort((a,b)=>a.n<b.n?-1:1);
  L("a82","Applied priorities mongo1=3, mongo2=2, mongo3=1");
  const old=primary(),pred=RS.m.filter(x=>x!==old).sort((a,b)=>b.prio-a.prio)[0];
  L("a82",`PREDICTION: ${pred.n} (highest priority secondary)`);await sleep(600);
  const {cand}=stepDown();L("a82",`rs.stepDown(30) on ${old.n}; new primary ${cand.n}`);
  await sleep(700);L("a82",`${old.n} barred for 30s, then takes primary back (priority takeover)`);
  LAB.a82.d={pred:pred.n,got:cand.n,took:(8+Math.random()*5).toFixed(0),back:(60+Math.random()*15).toFixed(0)};
  await sleep(500);const o=RS.m.find(x=>x.n==old.n);RS.m.forEach(x=>x.role="SECONDARY");o.role="PRIMARY"}
};
const noServer=async k=>{L(k,"Server not reachable (or Demo data is on): nothing was run. Start MongoDB and server.py, then press Run again.");throw new Error("not run")};
Object.assign(runs,{seed7:()=>noServer("seed7"),a71:()=>noServer("a71"),l72:()=>noServer("l72"),a72:()=>noServer("a72")});
async function refreshStatus(){
  const s=await fetch(`${API}/replica/status`).then(r=>r.json());
  RS.m.forEach(m=>{const x=s.members.find(y=>y.name==m.n);if(x)m.role=x.state});
  RS.arb=s.members.some(x=>x.state=="ARBITER")}
async function run(k){const l=LAB[k];if(l.st=="running")return;
  Object.assign(l,{st:"running",log:[],d:null,open:true});redraw();
  try{
    let r=null;if(!DEMO){try{r=await fetch(`${API}/replica/run/${k}`,{method:"POST"}).then(x=>x.json())}catch(e){r=null}}
    if(r){l.log=r.log.split("\n");l.st=r.ok?"passed":"failed";try{await refreshStatus()}catch(e){}}
    else{L(k,DEMO?"Demo data switched on: simulated run":"Server not reachable: running the demo simulation");await runs[k]();l.st="passed"}
    l.at=new Date().toLocaleTimeString()
  }catch(e){l.st="failed";L(k,String(e))}redraw()}
setInterval(()=>{if((location.hash.startsWith("#replica")||location.hash.startsWith("#cap")||location.hash.startsWith("#tx")||location.hash.startsWith("#shard")||location.hash.startsWith("#sec")||location.hash.startsWith("#cloud")||location.hash.startsWith("#ops")||location.hash.startsWith("#mon")||location.hash.startsWith("#mod")||location.hash.startsWith("#hybrid")||location.hash.startsWith("#tenants")||location.hash.startsWith("#cases")||location.hash.startsWith("#rag")||location.hash.startsWith("#ask")||location.hash.startsWith("#capstone"))&&!Object.values(LAB).some(l=>l.st=="running"))refreshStatus().then(redraw).catch(()=>{})},5000);
const card=(k,kind,title,body,shows)=>{const l=LAB[k];
  return `<article class="card lab"><div class="row" style="justify-content:space-between"><span class="kind mono">${kind}</span><span class="badge ${l.st}">${l.st=="idle"?"Not run":l.st=="running"?"Running":l.st=="passed"?"Passed":"Failed"}</span></div>
  <div class="meta">${title}</div>${l.d?body(l.d):`<h3>${l.st=="running"?"Running…":l.st=="idle"?"Press Run to start":(l.st=="passed"?"Real run passed. The output is in the log below. Switch on Demo data in the header to see the charts.":"The real run failed. The reason is in the log below.")}</h3>`}
  ${l.d?`<p><b>Shows:</b> ${shows}</p>`:""}
  <div class="foot"><span class="meta">${l.at?"Your run at "+l.at:"No result yet"}</span><span class="row"><button class="alt" data-log="${k}">${l.open?"Hide":"Show"} log</button><button data-run="${k}" ${l.st=="running"||ROLE=="Client"?"disabled":""} ${ROLE=="Client"?'title="Clients cannot run course labs"':""}>${l.st=="idle"?"Run":"Run again"}</button></span></div>
  ${l.open?`<div class="log">${esc(l.log.join("\n")||(l.st=="running"?"Running the real script. Its output appears here when it finishes (some labs take a few minutes).":"(no output)"))}</div>`:""}</article>`};
pages.replica=function(){
  const t=top100(),members=[...RS.m.map(x=>x),...(RS.arb?[{n:"mongo-arbiter",role:"ARBITER"}]:[])];
  const bar=m=>`<span>${m.n}<br><small class="meta">${m.role.toLowerCase()}</small></span><div class="bar"><i style="width:${m.docs}%;background:${COL[m.n]}"></i></div><span class="mono">${m.docs} of 100</span>`;
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 8: replica set</p>
  <div class="rs-head"><div><h1>Chapter 8: replica set</h1><p class="lead">A three-member MongoDB replica set copies Chapter 7's articles, survives the loss of its primary and elects a new one.</p>
  <span class="badge passed">Demo mode: simulated results</span></div>
  <div class="card"><b>Replica set <code>rs0</code></b> <span class="meta">members</span>
  <div class="members" style="margin-top:8px">${members.map(m=>`<div class="mem ${m.role}"><small>${m.role}</small><span class="dot" style="background:${COL[m.n]||"var(--mute)"}"></span>${m.n}</div>`).join("")}</div></div></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Chapter 7 data used</b><code>/api/articles/recent</code></div>
  <p>Latest 100 articles from Chapter 7 replicated into <code>cti_replica.articles</code></p>
  <div>${t.slice(0,5).map(a=>`<span class="tag">${esc(a.title)}</span>`).join("")}<span class="tag">+95 more</span></div></div>
  <div class="labs">
  ${card("l81","Lab 8.1","Deploy rs0 and replicate the latest articles",d=>`<h3>100 of 100 articles on every member</h3><div class="bars">${RS.m.map(bar).join("")}</div>`,"The replica set copies Chapter 7's data to all three servers.")}
  ${card("a81","Activity 8.1","Add an arbiter to rs0",d=>`<h3>Voting members went from 3 to 4; the set still tolerates 1 failure</h3>
    <div class="cmp">${[["Voting members","v"],["Majority needed","maj"],["Failures tolerated","tol"]].map(([n,f])=>`<span>${n}</span><span class="stat">${d.before[f]}</span><span>→</span><span class="stat" style="color:${f=="tol"?"var(--ok)":"var(--acc)"}">${d.after[f]}</span>`).join("")}</div>
    <p class="ok">Arbiter holds 0 articles · votes only, keeps no data</p>`,"An arbiter adds a vote without storing data, so it cannot add fault tolerance on its own.")}
  ${card("l82","Lab 8.2","Force a failover and watch the election",d=>`<h3>${d.nu} took over in about ${d.secs} s; ${d.reads.length} of ${d.reads.length} reads succeeded</h3>
    <div class="row"><span class="tag">${d.old}</span> old primary → <span class="tag" style="border-color:var(--warn)">${d.nu}</span> new primary</div>
    <div class="reads">${d.reads.map((n,i)=>`<span class="${i&&n!=d.reads[i-1]?"sw":""}" style="background:${COL[n]}" title="${n}">${i+1}</span>`).join("")}</div>
    <p class="ok">${d.reads.length} reads answered · 0 failed</p>`,"Reads of Chapter 7 articles keep working while the primary changes.")}
  ${card("a82","Activity 8.2","Priorities and predicting the next primary",d=>`<h3>Predicted ${d.pred}, elected ${d.got}</h3>
    <div class="card ${d.pred==d.got?"embed":"ref"}"><b>${d.pred}</b> predicted → <b>${d.got}</b> elected · <span class="${d.pred==d.got?"ok":"bad"}">${d.pred==d.got?"Correct":"Wrong"}</span></div>
    <div class="row">${RS.m.map(m=>`<span class="tag">${m.n} priority ${m.prio}</span>`).join("")}</div>
    <div class="grid" style="margin-top:8px"><div class="card"><span class="meta">Took over in</span><div class="stat">${d.took} s</div></div><div class="card"><span class="meta">Primary regained in</span><div class="stat">${d.back} s</div></div></div>`,"Member priorities decide who becomes primary.")}
  </div>
  <p class="meta" style="margin-top:16px">Real runs: <code>python lab8_1deployreplicaset.py</code>, <code>lab8_1_add_arbiter_try_it.py</code>, <code>lab8_2_observe_failover.py demo</code>, <code>lab8_2_priority_election_TRY_IT_YOURSELF.py</code> (ports 28017-28019).</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};

/* ===== Chapter 9: CAP theorem (simulated; real runs use the chapter-09 scripts via server.py) ===== */
["l91","a91","l92"].forEach(k=>LAB[k]={st:"idle",log:[],d:null,open:false});
const R=(a,b)=>a+Math.random()*(b-a),f2=x=>x.toFixed(2);
Object.assign(runs,{
async l91(){L("l91","Running 1,000 inserts with w:1 ...");await sleep(400);const a=R(1,1.6);
  L("l91","Running 1,000 inserts with w:majority ...");await sleep(400);const m=a*R(4.5,5.5);
  L("l91","Running 1,000 inserts with w:all (w:3) ...");await sleep(400);const al=a*R(2,2.6);
  LAB.l91.d={rows:[["w:1",a],["w:majority",m],["w:all (w:3)",al]]}},
async a91(){const rows=[];
  for(const [n,base,add] of [["w:1",.7,[2.5,3.2]],["w:majority",4.2,[.5,1]],["w:all (w:3)",2,[2.8,3.4]]]){
    L("a91",`${n}: 1,000 inserts with j:false, then j:true ...`);await sleep(450);
    const f=base*R(.9,1.1);rows.push([n,f,f+R(...add)])}
  LAB.a91.d={rows}},
async l92(){const tl=[];const t=(s,x)=>{tl.push([s,x]);L("l92",`[${s} s] ${x}`)};
  t(0,"partition A starts: mongo1 isolated");await sleep(500);
  t(12.7,"primary reports mongo1 as not reachable (13 s after the cut)");await sleep(400);
  t(32.3,"partition A ends: mongo1 reconnected after 32 s");t(33.3,"mongo1 has caught up (1.0 s after reconnecting)");await sleep(400);
  t(34.8,"partition B starts: mongo1 and mongo3 isolated, mongo2 alone");await sleep(500);
  t(44.6,"mongo2 steps down: no majority for 9.8 s, no primary left");await sleep(400);
  t(53.8,"partition B ends: mongo1 and mongo3 reconnected after 19 s");
  t(56,"mongo1 elected primary 2.2 s after reconnecting");t(56,"all three members healthy again");
  LAB.l92.d={tl,stats:[["Detected after","13 s"],["Caught up after","1.0 s"],["Stepped down after","9.8 s"],["Re-elected after","2.2 s"],["Writes kept","2"],["Reads while cut off","Still worked"]]}}
});
const OUT={ok:["Succeeded","o s"],to:["Timed out","o t"],fail:["Failed","o f"],no:["not tried","o n"]};
const cell=(...xs)=>`<td>${xs.map(([k,ms])=>`<div class="${OUT[k][1]}">${OUT[k][0]}${ms?` ${ms} ms`:""}</div>`).join("")}</td>`;
const barRow=(lbl,v,max,color,p95)=>`<div class="bars" style="grid-template-columns:90px 1fr 70px"><span class="mono">${lbl}</span><div class="bar"><i style="width:${v/max*100}%;background:${color}"></i></div><span class="mono">${f2(v)} ms</span></div>`;
pages.cap=function(){
  const members=RS.m;
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 9: CAP theorem</p>
  <div class="rs-head"><div><h1>Chapter 9: CAP theorem</h1><p class="lead">The CAP theorem with Chapter 7's threat data: stronger write guarantees cost latency, and a network partition makes MongoDB refuse writes to stay consistent.</p><span class="badge passed">Demo mode: simulated results</span></div>
  <div class="card"><b>Replica set <code>rs0</code></b><div class="members" style="margin-top:8px">${members.map(m=>`<div class="mem ${m.role}"><small>${m.role}</small><span class="dot" style="background:${COL[m.n]}"></span>${m.n}</div>`).join("")}</div></div></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Chapter 7 data used</b><code>/api/articles/recent</code></div><p>Latest articles from Chapter 7, written by the Chapter 9 labs</p>
  <div class="row"><div class="card" style="margin:0"><span class="stat">3,000</span> <code>latency_lab.w_*</code> <span class="meta">Lab 9.1</span></div><div class="card" style="margin:0"><span class="stat">6,000</span> <code>latency_lab.w_*_j_*</code> <span class="meta">Activity 9.1</span></div><div class="card" style="margin:0"><span class="stat">21</span> <code>partition_lab.writes</code> <span class="meta">Lab 9.2</span></div></div>
  <div style="margin-top:8px">${top100().slice(0,4).map(a=>`<span class="tag">${esc(a.title)}</span>`).join("")}<span class="tag">+95 more</span></div></div>
  <div class="labs">
  ${card("l91","Lab 9.1","Latency of w:1, w:majority and w:all",d=>{const mx=Math.max(...d.rows.map(r=>r[1]))*1.2,b=d.rows[0][1];
    return `<h3>w:majority is ${(d.rows[1][1]/b).toFixed(1)}x slower than w:1</h3><p class="meta">1,000 Chapter 7 events per write concern</p>${d.rows.map((r,i)=>barRow(r[0],r[1],mx,"var(--m1)")+`<div class="meta" style="text-align:right">${i?`x${(r[1]/b).toFixed(2)} vs w:1`:"baseline"}</div>`).join("")}`},"Waiting for more members to confirm a write costs latency.")}
  ${card("a91","Activity 9.1","Journaling with j:false and j:true",d=>{const mx=Math.max(...d.rows.map(r=>r[2]))*1.15,o=d.rows[0][2]-d.rows[0][1];
    return `<h3>Journaling adds about ${o.toFixed(0)} ms per write at w:1</h3><p class="meta">1,000 events per setting, with the journal wait (j:true) and without (j:false)</p>${d.rows.map(r=>`<div class="row" style="justify-content:space-between"><b class="mono">${r[0]}</b><span class="badge" style="color:var(--warn);border-color:var(--warn)">+${f2(r[2]-r[1])} ms with j:true</span></div>${barRow("j:false",r[1],mx,"var(--m1)")}${barRow("j:true",r[2],mx,"var(--m2)")}`).join("")}`},"Waiting for the disk journal before acknowledging a write adds latency, though timing noise can hide it at some levels.")}
  <div style="grid-column:1/-1">${card("l92","Lab 9.2","Network partition",d=>`<h3>Writes needing a majority stopped while the primary was alone</h3><p class="meta">200 Chapter 7 events as the write target</p>
    <div class="split"><div style="overflow-x:auto"><table><tr><th>Phase</th><th class="mono">w:1</th><th class="mono">w:majority</th><th class="mono">w:all</th></tr>
    <tr><td>Healthy</td>${cell(["ok",25])}${cell(["ok",35])}${cell(["ok",2])}</tr>
    <tr><td>One secondary cut off</td>${cell(["ok",1])}${cell(["ok",5])}${cell(["to",5019])}</tr>
    <tr><td>Primary alone</td>${cell(["ok",1],["fail",5008])}${cell(["to",5013])}${cell(["no"])}</tr>
    <tr><td>Reconnected</td>${cell(["no"])}${cell(["ok",11])}${cell(["no"])}</tr></table></div>
    <div><div class="grid" style="grid-template-columns:1fr 1fr">${d.stats.map(([k,v])=>`<div class="card" style="margin:0"><span class="meta">${k}</span><div class="stat" style="font-size:1.3rem">${v}</div></div>`).join("")}</div>
    <ol style="list-style:none;padding:0;margin:12px 0 0">${d.tl.map(([s,x],i)=>`<li class="row" style="align-items:flex-start;gap:8px"><span class="badge mono">${i+1}</span><span class="mono" style="min-width:52px">${s} s</span><span>${esc(x)}</span></li>`).join("")}</ol></div></div>`,"During a partition MongoDB keeps consistency and gives up write availability (CP).")}</div>
  </div>
  <p class="meta" style="margin-top:16px">Real runs: <code>lab9_1_write_concern_latency.py</code>, <code>Activity for 9.1 - Try it yourself.py</code>, <code>Lab 9.2 - Simulate a network partition.py</code>. With the server running, Run executes them and Show log prints their output.</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};

/* ===== Chapter 10: transactions (simulated; real runs use the chapter-10 scripts via server.py) ===== */
["l101","a101","l102"].forEach(k=>LAB[k]={st:"idle",log:[],d:null,open:false});
Object.assign(runs,{
async l101(){L("l101","Initial balances: alice 500, bob 100");await sleep(400);
  L("l101","Transfer 200 alice -> bob: alice 300 after debit, COMMITTED");await sleep(500);
  L("l101","Transfer 1000 alice -> bob: alice -700 inside the transaction, ABORTED");await sleep(500);
  L("l101","Verified: failed transfer rolled back, 1 transfer recorded");
  LAB.l101.d={}},
async a101(){const n=10,retries=Math.round(R(15,25)),fail=Math.random()<.4?1:0,ok=n-fail;
  L("a101",`${n} concurrent transfers of 10 from alice to bob`);
  for(let i=0;i<6;i++){await sleep(250);L("a101",`write conflict, retry ${i+1}/6 in ${(0.1*2**i).toFixed(1)} s`)}
  L("a101","Test 2: insufficient funds fails immediately, no retry");
  LAB.a101.d={n,ok,fail,retries,alice:1000-10*ok,bob:1000+10*ok}},
async l102(){L("l102","Demo: 8 simultaneous requests, 5 in stock");await sleep(500);
  const noRetryRes=Math.round(R(3,5));L("l102","Throughput: 1, 4, 8, 16 threads");await sleep(600);
  const tx=[41.7,46,56.2,72.1].map(v=>v*R(.92,1.08)),fm=[165.2,387.2,483.7,663.6].map(v=>v*R(.92,1.08));
  L("l102","Consistency: 10% of requests fail after the stock decrement");await sleep(500);
  LAB.l102.d={noRetryRes,tx,fm,leak:Math.round(R(6,11))}}
});
const chart=(tx,fm)=>{const W=440,H=230,L0=40,xs=[1,4,8,16],mx=700,X=t=>L0+xs.indexOf(t)/3*(W-L0-14),Y=v=>H-28-v/mx*(H-48);
  const ln=(a,c)=>`<polyline fill="none" style="stroke:${c}" stroke-width="2.5" points="${xs.map((t,i)=>X(t)+","+Y(a[i])).join(" ")}"/>`+xs.map((t,i)=>`<circle cx="${X(t)}" cy="${Y(a[i])}" r="4" style="fill:${c}"/>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Throughput by concurrency level">
  ${[0,200,400,600].map(v=>`<line x1="${L0}" x2="${W-10}" y1="${Y(v)}" y2="${Y(v)}" style="stroke:var(--line)"/><text x="${L0-6}" y="${Y(v)+4}" text-anchor="end" font-size="11" style="fill:var(--mute)">${v}</text>`).join("")}
  ${xs.map(t=>`<text x="${X(t)}" y="${H-10}" text-anchor="middle" font-size="11" style="fill:var(--mute)">${t}</text>`).join("")}
  ${ln(tx,"var(--m2)")}${ln(fm,"var(--warn)")}
  <text x="${L0+8}" y="16" font-size="12" style="fill:var(--m2)">transactional</text><text x="${L0+110}" y="16" font-size="12" style="fill:var(--warn)">findAndModify</text></svg>
  <div class="meta" style="text-align:center">Concurrent threads (x) and successful reservations per second (y)</div>`};
pages.tx=function(){
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 10: transactions</p>
  <div class="rs-head"><div><h1>Chapter 10: transactions</h1><p class="lead">Multi-document transactions on the replica set: a transfer happens completely or not at all, write conflicts are retried, and plain updates can leak stock when something fails halfway.</p><span class="badge passed">Demo mode: simulated results</span></div>
  <div class="card"><b>Replica set <code>rs0</code></b><div class="members" style="margin-top:8px">${RS.m.map(m=>`<div class="mem ${m.role}"><small>${m.role}</small><span class="dot" style="background:${COL[m.n]}"></span>${m.n}</div>`).join("")}</div></div></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Data used</b><code>chapter-10 database</code></div>
  <div class="row"><div class="card" style="margin:0"><code>accounts</code> <code>history</code> <span class="meta">Lab 10.1, Activity 10.1</span></div><div class="card" style="margin:0"><code>inventory</code> <code>orders</code> <span class="meta">Lab 10.2</span></div></div></div>
  <div class="labs">
  ${card("l101","Lab 10.1","Bank transfer transaction",d=>`<h3>Valid transfer committed; the overdraft rolled back</h3>
    <div class="grid" style="grid-template-columns:1fr 1fr"><div class="card embed" style="margin:0"><b>Transfer 200</b><div class="ok">COMMITTED</div><div class="meta">alice 500 → 300<br>bob 100 → 300</div></div>
    <div class="card ref" style="margin:0"><b>Transfer 1000</b><div class="bad">ABORTED</div><div class="meta">alice -700 inside the transaction<br>balances after: 300 and 300</div></div></div><p class="ok">1 transfer recorded (only the successful one)</p>`,"The abort undoes a debit that was already applied inside the transaction.")}
  ${card("a101","Activity 10.1","Retry with exponential backoff",d=>`<h3>${d.ok} of ${d.n} concurrent transfers committed after ${d.retries} retries</h3>
    <div class="row">${[0,1,2,3,4,5].map(i=>`<span class="tag">retry ${i+1}: ${(0.1*2**i).toFixed(1)} s</span>`).join("")}</div>
    <div class="cmp"><span>alice</span><span class="stat">${d.alice}</span><span></span><span></span><span>bob</span><span class="stat">${d.bob}</span><span></span><span></span></div>
    <p class="${d.fail?"bad":"ok"}">${d.fail?"1 transfer ran out of retries (still a WriteConflict)":"No transfer ran out of retries"} · total money unchanged at 2000</p><p class="meta">Insufficient funds fails immediately and is not retried.</p>`,"Only TransientTransactionError is retried; a business error like insufficient funds is not.")}
  <div style="grid-column:1/-1">${card("l102","Lab 10.2","Inventory reservation with deadlock handling",d=>`<h3>Transactions stay consistent; plain updates leaked ${d.leak} units</h3>
    <div class="split"><div>${chart(d.tx,d.fm)}</div><div>
    <div class="card" style="margin:0 0 10px"><b>8 requests, 5 in stock</b><p class="meta" style="margin:4px 0">Without retry: ${d.noRetryRes} reserved, ${8-d.noRetryRes} conflict.<br>With retry: 5 reserved, 3 out of stock, final stock 0.</p></div>
    <div class="grid" style="grid-template-columns:1fr 1fr"><div class="card embed" style="margin:0"><b>transactional</b><div class="ok">0 leaked units</div></div><div class="card ref" style="margin:0"><b>findAndModify</b><div class="bad">${d.leak} leaked units</div></div></div>
    <p class="meta">findAndModify is faster, but stock was decremented without an order when a failure hit between the two writes.</p></div></div>`,"A transaction costs throughput but rolls back cleanly when something fails halfway.")}</div>
  </div>
  <p class="meta" style="margin-top:16px">Real runs: <code>Lab 10.1 - Bank transfer transaction.py</code>, <code>Activity for 10.1 - Try it yourself.py</code>, <code>Lab 10.2 - Inventory reservation with deadlock handling.py</code>.</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};

/* ===== Chapter 11: sharding (simulated; real runs use the chapter-11 scripts against the mongos on port 27117) ===== */
["l111","a111","l112"].forEach(k=>LAB[k]={st:"idle",log:[],d:null,open:false});
const KEYS=[["order_id","#1f77b4"],["customer_id","#ff7f0e"],["order_date","#2ca02c"],["hashed customer_id","#d62728"]];
const LIVE=[[0,0,0,100],[6,8,12,73],[0,0,0,100],[24,25,27,24]];
const ALLD=[[12,12,12,62],[17,16,19,48],[12,13,12,63],[22,25,28,25]];
const SCORE=[2.30,2.70,1.70,3.90],IMB=["4.00x","2.93x","4.00x","1.08x"];
Object.assign(runs,{
async l111(){L("l111","Simulating 100,000 orders, 5,000 customers, 4 shards, ~64 chunks (seed 42)");await sleep(500);
  L("l111","1. Cardinality  2. Distribution  3. Query targeting");await sleep(500);
  L("l111","4. Decision matrix: hashed customer_id scores 3.90 / 5.00");LAB.l111.d={}},
async a111(){const steps=["Preflight: mongos router, version >= 5.0, collection sharded, no index builds","Balancer stopped","reshardCollection chapter-11.orders {order_id: 1} -> {customer_id: hashed}","Monitoring: donors copy documents to recipients","commitReshardCollection: writes block briefly","Balancer started again"];
  for(const s of steps){await sleep(450);L("a111",s)}
  LAB.a111.d={secs:Math.round(R(300,340)),steps,before:{shard1rs:2,shard2rs:1},after:{shard1rs:2,shard2rs:2}}},
async l112(){L("l112","Sharding hotspot_data on {ts: 1} and even_data on {user_id: hashed}");await sleep(500);
  L("l112","Inserted 10,000 documents into each collection");await sleep(500);
  L("l112","Waiting for the balancer ... then explain() on range queries");await sleep(600);
  const h=Math.round(R(71,76));LAB.l112.d={h,ev:Math.round(R(49,51))}}
});
const gbars=(data,title)=>{const W=330,H=190,L0=30,gw=(W-L0-8)/4,bw=gw/5,Y=v=>H-24-v/100*(H-44);
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="${title}"><text x="${L0}" y="14" font-size="12" style="fill:var(--ink)">${title}</text>
  ${[0,25,50,100].map(v=>`<line x1="${L0}" x2="${W-6}" y1="${Y(v)}" y2="${Y(v)}" style="stroke:var(--line)" ${v==25?'stroke-dasharray="4"':""}/><text x="${L0-4}" y="${Y(v)+4}" text-anchor="end" font-size="10" style="fill:var(--mute)">${v}</text>`).join("")}
  ${[0,1,2,3].map(s=>`<text x="${L0+gw*s+gw/2}" y="${H-8}" text-anchor="middle" font-size="10" style="fill:var(--mute)">shard${s}</text>`+data.map((row,k)=>`<rect x="${L0+gw*s+bw*(k+.5)}" y="${Y(row[s])}" width="${bw*.9}" height="${Math.max(0,H-24-Y(row[s]))}" fill="${KEYS[k][1]}"><title>${KEYS[k][0]}: ${row[s]}%</title></rect>`).join("")).join("")}</svg>`};
pages.shard=function(){
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 11: sharding</p>
  <div class="rs-head"><div><h1>Chapter 11: sharding</h1><p class="lead">Orders on a sharded cluster: the shard key decides where writes go and how many shards a query asks, and it can be changed on a live collection.</p><span class="badge passed">Demo mode: simulated results</span></div>
  <div class="card"><b>Sharded cluster</b><div class="members" style="margin-top:8px">${[["ROUTER","mongos :27117","PRIMARY"],["SHARD","shard1rs","SECONDARY"],["SHARD","shard2rs","SECONDARY"],["CONFIG","cfgrs","ARBITER"]].map(([r,n,c])=>`<div class="mem ${c}"><small>${r}</small>${n}</div>`).join("")}</div></div></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Data used</b><code>chapter-11 database</code></div><p>Orders from Chapter 7's scans, sharded in different ways</p>
  <div class="row"><div class="card" style="margin:0"><span class="stat">50,000</span> <code>orders</code> <span class="meta">Activity 11.1</span></div><div class="card" style="margin:0"><span class="stat">10,000</span> <code>hotspot_data</code> <span class="meta">Lab 11.2</span></div><div class="card" style="margin:0"><span class="stat">10,000</span> <code>even_data</code> <span class="meta">Lab 11.2</span></div></div></div>
  <div class="labs">
  <div style="grid-column:1/-1">${card("l111","Lab 11.1","Four shard keys for the orders, measured",d=>`<h3>Recommended: hashed customer_id (3.90 / 5.00)</h3>
    <div class="split"><div>${gbars(LIVE,"Share of live writes per shard (%)")}</div><div>${gbars(ALLD,"Share of all data per shard (%)")}</div></div>
    <div class="row" style="margin:6px 0">${KEYS.map(k=>`<span class="tag"><span class="dot" style="background:${k[1]}"></span>${k[0]}</span>`).join("")}</div>
    <table><tr><th>Shard key</th><th>Write imbalance</th><th>Score (max 5)</th></tr>${KEYS.map((k,i)=>`<tr><td>${k[0]}</td><td class="mono">${IMB[i]}</td><td class="mono ${i==3?"ok":""}">${SCORE[i].toFixed(2)}</td></tr>`).join("")}</table>
    <p class="meta">Trade-off: with a hashed customer_id, 50% of the traffic goes to a single shard; lookups by order_id and date-range reports ask every shard.</p>`,"A hashed customer_id spreads writes evenly and still sends a customer's history to one shard; a date key sends every new order to one shard.")}</div>
  ${card("a111","Activity 11.1","Reshard a live collection",d=>`<h3>Resharded to hashed customer_id in ${d.secs} s</h3>
    <ol style="list-style:none;padding:0;margin:8px 0">${d.steps.map((s,i)=>`<li class="row" style="align-items:flex-start;gap:8px"><span class="badge ok">${i+1}</span><span>${esc(s)}</span></li>`).join("")}</ol>
    <div class="grid" style="grid-template-columns:1fr 1fr"><div class="card ref" style="margin:0"><b>Before</b><div class="meta"><code>{order_id: 1}</code><br>chunks: ${Object.entries(d.before).map(([k,v])=>k+" "+v).join(", ")}</div></div><div class="card embed" style="margin:0"><b>After</b><div class="meta"><code>{customer_id: hashed}</code><br>chunks: ${Object.entries(d.after).map(([k,v])=>k+" "+v).join(", ")}</div></div></div>`,"Since 5.0 a shard key can change on a live collection; writes wait only for the commit, about 2 s.")}
  ${card("l112","Lab 11.2","Shard key hotspot",d=>`<h3>Timestamp key: ${d.h}% on one shard; hashed key: ${d.ev}% at most</h3>
    <table><tr><th>Collection</th><th class="mono">shard1rs</th><th class="mono">shard2rs</th></tr>
    <tr><td>hotspot_data <code>{ts: 1}</code></td><td class="mono bad">${d.h}%</td><td class="mono">${100-d.h}%</td></tr>
    <tr><td>even_data <code>{user_id: hashed}</code></td><td class="mono ok">${d.ev}%</td><td class="mono ok">${100-d.ev}%</td></tr></table>
    <table style="margin-top:8px"><tr><th>Query</th><th>Shards touched</th></tr><tr><td>ts range, full year</td><td>2 of 2</td></tr><tr><td>ts range, last 5 days</td><td class="ok">1 (targeted)</td></tr><tr><td>user_id range (hashed)</td><td>2 of 2</td></tr><tr><td>user_id equality (hashed)</td><td class="ok">1 (targeted)</td></tr></table>`,"An always-increasing key sends every insert to the last chunk, one shard; hashing spreads them but turns range queries into scatter-gather.")}
  </div>
  <p class="meta" style="margin-top:16px">Real runs need the sharded cluster: <code>docker compose -f docker-compose-sharded.yml up -d</code>, then <code>Lab 11.1</code>, <code>Activity for 11.1</code> and <code>Lab 11.2</code> in the chapter-11 folder. Resharding takes at least about 5 minutes.</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};

/* ===== Chapter 12: security (results below are the recorded runs of your scripts; real runs need mongo-auth on 27028 and Docker) ===== */
["l121","a121","a122"].forEach(k=>LAB[k]={st:"idle",log:[],d:null,open:false});
Object.assign(runs,{
async l121(){const s=["Step 1: unauthenticated access rejected (not authorized)","Step 2: sample data created in chapter-12, chapter-12-bookstore, chapter-12-hr","Step 3: roles limitedWriter, hrReader, viewReader and 5 users created","Step 4: logged in as each user and tested 17 operations","17/17 checks passed"];
  for(const t of s){await sleep(450);L("l121",t)}LAB.l121.d={}},
async a121(){const s=["Step 1: employees (4 docs with salary) and view employees_public created","Step 2: roles hrRole, staffRole; users hr_manager, staff_user, dev_user","Step 3: 9 checks run","9/9 checks passed. dev_user bypasses the view"];
  for(const t of s){await sleep(450);L("a121",t)}LAB.a121.d={}},
async a122(){const s=["Generating certificates: CA -> server (SAN localhost, 127.0.0.1) and client","Starting mongo-tls with --tlsMode requireTLS","Negotiated TLS: TLSv1.3, cipher TLS_AES_256_GCM_SHA384","5/5 checks passed"];
  for(const t of s){await sleep(450);L("a122",t)}LAB.a122.d={}}
});
const PERM=[["analyst","read@chapter-12, read@chapter-12-bookstore",[["find products",1],["find books",1],["insert products",0],["delete products",0]]],
["app_writer","readWrite@chapter-12",[["find products",1],["insert products",1],["delete products",1],["find books",0]]],
["log_writer","limitedWriter@admin",[["find products",1],["insert logs",1],["update logs",1],["delete logs",0],["insert products",0]]],
["view_user","viewReader@admin",[["find employees_public (salary hidden)",1],["find employees",0]]],
["hr_user","hrReader@admin",[["find employees (salary visible)",1],["insert employees",0]]]];
const RED=[["staff_user","find on view employees_public",1,"4 docs, salary hidden"],["staff_user","aggregate headcount on the view",1,"3 groups"],["staff_user","aggregate payroll total on the view",1,"total payroll = 0 (field not visible)"],["staff_user","filter salary > 50000 on the view",1,"0 docs match: cannot probe salaries"],["staff_user","find on employees (real collection)",0,"not authorized"],["staff_user","insert into the view",0,"not authorized"],["hr_manager","find on employees (real collection)",1,"salary VISIBLE"],["hr_manager","update on employees",0,"not authorized"],["dev_user","find on employees (pitfall)",1,"salary VISIBLE (bypasses the view!)"]];
const TLSR=[["Plain (non-TLS) connection is rejected","ServerSelectionTimeoutError"],["TLS without client certificate is rejected","ServerSelectionTimeoutError"],["TLS with untrusted CA is rejected","ServerSelectionTimeoutError"],["TLS + CA + client cert: find_one() works",""],["Connection uses modern TLS (TLSv1.3)",""]];
const RMX=[["Read the feed, threats, reports and stored file reports",1,1,1],["Pay for and run file scans",1,1,1],["See their own scans, payments and invoices",1,1,1],["See every customer's payments and invoices",0,1,1],["Read the sandbox log (every file run in the sandbox)",0,1,1],["Run course lab activities",0,1,1],["Refund a payment",0,0,1],["Create users, change roles, disable accounts",0,0,1]];
const RN=["Client","Moderator","Administrator"];
pages.sec=function(){
  const chip=([t,a])=>`<span class="tag ${a?"t-embed":"t-ref"}">${a?"✓":"✗"} ${esc(t)}</span>`;
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 12: security</p>
  <div class="rs-head"><div><h1>Chapter 12: security</h1><p class="lead">Chapter 7's data on a server that needs a user and TLS: each role reaches only what it should, salaries are redacted for non-HR users, and unencrypted connections are refused.</p><span class="badge passed">Results shown are the recorded runs of your scripts</span></div>
  <div class="card"><b>Secured server</b><div class="members" style="margin-top:8px">${[["FULL ACCESS","admin"],["ROLE","analyst, app_writer"],["CUSTOM ROLE","log_writer"],["REQUIRES TLS","mongo-tls :27029"]].map(([r,n])=>`<div class="mem"><small>${r}</small>${n}</div>`).join("")}</div></div></div>
  <div class="card"><b>What each role can do</b> <span class="meta">(your role: ${ROLE})</span><div style="overflow-x:auto"><table><tr><th>Can</th>${RN.map(r=>`<th ${r==ROLE?'style="color:var(--acc)"':""}>${r}</th>`).join("")}</tr>
  ${RMX.map(r=>`<tr><td>${r[0]}</td>${[1,2,3].map(i=>`<td class="${r[i]?"ok":""}">${r[i]?"✓":"–"}</td>`).join("")}</tr>`).join("")}</table></div></div>
  <div class="labs">
  ${card("l121","Lab 12.1","Authentication and role-based access",d=>`<h3>17 of 17 checks passed: every user can do only what its role allows</h3>
    ${PERM.map(([u,r,ops])=>`<div style="margin:8px 0"><b class="mono">${u}</b> <span class="meta">${r}</span><div>${ops.map(chip).join("")}</div></div>`).join("")}
    <p class="ok">Unauthenticated access to listDatabases and to products was rejected (not authorized).</p>`,"With --auth every request needs a user, and each role reaches only the operations it was given.")}
  ${card("a121","Activity 12.1","Field-level redaction with a view",d=>`<h3>9 of 9 checks passed; staff see no salary, but dev_user bypasses the view</h3>
    <div style="overflow-x:auto"><table><tr><th>User</th><th>Operation</th><th>Result</th></tr>${RED.map(([u,o,a,n])=>`<tr><td class="mono">${u}</td><td>${o}<div class="meta">${esc(n)}</div></td><td class="${a?"ok":"bad"}">${a?"allowed":"denied"}</td></tr>`).join("")}</table></div>
    <div class="card ref" style="margin:8px 0 0"><b>Pitfall</b><div class="meta">dev_user has the broad read role on the database, so the view does not restrict them. Grant find on the view only, never read on the whole database.</div></div>`,"A view with $project redacts fields per role: privileges are checked on the view itself.")}
  <div style="grid-column:1/-1">${card("a122","Activity 12.2","TLS, encryption in transit",d=>`<h3>3 insecure connections refused; TLSv1.3 with TLS_AES_256_GCM_SHA384 and a client certificate works</h3>
    <div class="split"><div><table><tr><th>Check</th><th>Result</th></tr>${TLSR.map(([c,e])=>`<tr><td>${c}${e?`<div class="meta">${e}</div>`:""}</td><td class="ok">PASS</td></tr>`).join("")}</table></div>
    <div><b>Certificate chain</b><pre>MongoDB-CA (self-signed root)
 ├─ server.crt  CN=mongodb
 │              SAN localhost, mongodb, 127.0.0.1
 └─ client.crt  CN=pymongo-client

Both signed by MongoDB-CA: OK
Valid 2026-11-14 to 2027-11-14</pre></div></div>`,"requireTLS rejects every unencrypted or unverified connection: data only moves encrypted.")}</div>
  </div>
  <p class="meta" style="margin-top:16px">Real runs: <code>Lab 12.1 - Authentication and RBAC.py</code>, <code>Activity for 12.1 - Try it yourself.py</code> (need the <code>mongo-auth</code> container on port 27028) and <code>Activity for 12.2 - Try it yourself.py</code> (needs <code>pip install cryptography</code> and Docker).</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};

/* ===== Chapter 13: containers and the cloud + Operations (Deployment). Lab results are from your recorded runs;
   the Operations charts are simulated unless you connect Prometheus through server.py ===== */
["l131","a131","l132"].forEach(k=>LAB[k]={st:"idle",log:[],d:null,open:false});
const C13={m:[{n:"lab13-rs1",role:"PRIMARY"},{n:"lab13-rs2",role:"SECONDARY"},{n:"lab13-rs3",role:"SECONDARY"}],segs:[{at:0,p:"lab13-rs1"}],elections:0,audit:[],range:30,busy:false,msg:""};
const C13COL={"lab13-rs1":"#2f6fd0","lab13-rs2":"#5b5bd6","lab13-rs3":"#8a5bd6"};
Object.assign(runs,{
async l131(){for(const t of["docker compose -f docker-compose-production.yml up -d (rs-mongo1, rs-mongo2, rs-mongo3)","init-replica-set.js: rs.initiate and admin user rsadmin","Failover test: reading and majority-writing for 40 s","[5.1s] replSetStepDown on mongo2:27027 -> PRIMARY CHANGED to mongo1","Reads ok: 325  Writes ok: 325  Errors: 0  Longest pause 0.2 s","RESULT: PASS - failover worked, no data lost"]){await sleep(420);L("l131",t)}LAB.l131.d={}},
async a131(){for(const t of["create-monitor-user.js: user exporter (clusterMonitor + read on local)","docker compose -f docker-compose-production.yml -f docker-compose-monitoring.yml up -d","mongodb-exporter (percona 0.40) answering on :9216/metrics","Prometheus v2.55.1 scrapes mongodb-exporter:9216 every 15 s: target up"]){await sleep(420);L("a131",t)}LAB.a131.d={}},
async l132(){for(const t of["Using Kubernetes context: docker-desktop","Secret mongo-keyfile, headless Service and StatefulSet applied (3 pods, 3 PVCs)","rs.initiate from mongo-0; admin user created","Deleting pod mongo-2 ...","mongo-2 recreated (new pod UID), rejoined as SECONDARY in 32 s","9/9 checks passed"]){await sleep(420);L("l132",t)}LAB.l132.d={}}
});
const K8S=[["3 pods Running and Ready","mongo-0, mongo-1, mongo-2 = Running/true"],["3 PersistentVolumeClaims Bound","Bound, Bound, Bound"],["Members use stable DNS names","mongo-N.mongo-headless-svc:27017"],["1 PRIMARY + 2 SECONDARY, all healthy",""],["Majority write through the replica set URI",""],["Kubernetes recreated pod mongo-2 (new pod UID)","41e07359 → 91520a5d"],["mongo-2 rejoined as SECONDARY","back in 32 s (pod Ready after 31 s)"],["Same PersistentVolumeClaim reattached (data-mongo-2)",""],["Data still present on the recreated pod","documents seen on mongo-2: 3"]];
const stat=(k,v)=>`<div class="card" style="margin:0"><span class="meta">${k}</span><div class="stat" style="font-size:1.25rem">${v}</div></div>`;
pages.cloud=function(){
  const mem=C13.m;
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 13: containers and the cloud</p>
  <div class="rs-head"><div><h1>Chapter 13: containers and the cloud</h1><p class="lead">Chapter 7's data deployed three ways: a keyfile replica set in Docker Compose that keeps serving reads through a failover and is watched by Prometheus, a Kubernetes StatefulSet that heals a deleted pod, and an Atlas cluster made by Terraform.</p><span class="badge passed">Lab results shown are your recorded runs</span></div>
  <div class="card"><b>Replica set <code>rs0</code></b><div class="members" style="margin-top:8px">${mem.map(m=>`<div class="mem ${m.role}"><small>${m.role}</small><span class="dot" style="background:${C13COL[m.n]}"></span>${m.n}</div>`).join("")}</div></div></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Chapter 7 data used</b><code>chapter-13 database</code></div><p>The latest events from Chapter 7, kept on the keyfile replica set <code>rs0</code></p>
  <div class="row"><div class="card" style="margin:0"><span class="stat">325</span> <code>failover</code> <span class="meta">written by Lab 13.1</span></div><div class="card" style="margin:0"><span class="stat">3</span> <code>items</code> <span class="meta">Lab 13.2, on every pod</span></div></div></div>
  <h2>Live from the lab</h2>
  <div class="labs">
  <div class="card"><b>Last failover (Lab 13.1)</b><p class="meta">The primary stepped down while a PyMongo reader kept reading and writing: how fast a new primary took over.</p>
    <div class="grid" style="grid-template-columns:1fr 1fr">${stat("Primary","mongo2 → mongo1")}${stat("Longest pause","0.2 s")}${stat("Reads and writes","325 / 325, 0 failed")}${stat("Documents stored","325")}</div></div>
  <div class="card"><b>Monitoring (Activity 13.1)</b><p class="meta">The exporter sidecar turns serverStatus into Prometheus metrics at <code>:9216</code>; Prometheus scrapes it every 15 s.</p>
    <div class="grid" style="grid-template-columns:1fr 1fr">${stat("Exporter","percona 0.40 on :9216")}${stat("Prometheus target","mongodb-exporter → up")}</div>
    <div class="row" style="margin-top:10px"><a class="tag" href="http://localhost:9090" target="_blank" rel="noopener">Prometheus ↗</a><a class="tag" href="http://localhost:9216/metrics" target="_blank" rel="noopener">Exporter metrics ↗</a><a class="tag" href="#ops">Operations charts</a></div></div>
  <div class="card"><b>Kubernetes StatefulSet (Lab 13.2)</b><p class="meta">mongo-0, mongo-1 and mongo-2 on Docker Desktop Kubernetes, each with its own volume.</p>
    <div class="row">${["mongo-0","mongo-1","mongo-2"].map(p=>`<span class="tag t-embed">${p} Ready</span>`).join("")}</div>
    <div class="grid" style="grid-template-columns:1fr 1fr;margin-top:8px">${stat("Deleted pod back","32 s as SECONDARY")}${stat("Its data","3 / 3 documents, same volume")}</div></div>
  <div class="card"><b>Atlas, made by Terraform</b><p class="meta">A free M0 cluster in a separate Atlas project, created from one <code>main.tf</code>. The live site's cluster is untouched.</p>
    <div class="card ref" style="margin:0"><b>Not run yet</b><div class="meta">Needs an Atlas organisation API key with the Organization Project Creator role. No Terraform files were provided for this lab, so there is nothing to run here yet.</div></div></div>
  </div>
  <h2>Labs</h2><div class="labs">
  ${card("l131","Lab 13.1","A replica set with keyfile authentication, and its failover",d=>`<h3>3 of 3 members healthy with keyfile auth; primary mongo2 → mongo1, 0 operations failed</h3>
    <div class="grid" style="grid-template-columns:1fr 1fr 1fr">${stat("Reads ok","325")}${stat("Writes ok (majority)","325")}${stat("Errors","0")}</div>
    <p class="ok" style="margin-top:8px">PASS: failover worked, no data lost (longest pause between successful operations 0.2 s).</p>`,"Members that share a keyfile form an authenticated replica set, and a reader with retryable reads rides through an election.")}
  ${card("a131","Activity 13.1","A Prometheus exporter sidecar",d=>`<h3>The exporter publishes serverStatus metrics; the Prometheus target is up</h3>
    <ol style="margin:8px 0;padding-left:20px"><li>Least-privilege user <code>exporter</code>: clusterMonitor on admin, read on local</li><li>Sidecar <code>percona/mongodb_exporter:0.40</code> reads mongo1 directly</li><li>Prometheus v2.55.1 scrapes <code>mongodb-exporter:9216</code> every 15 s</li></ol>`,"An exporter next to the member turns serverStatus and rs.status() into metrics that Prometheus stores.")}
  <div style="grid-column:1/-1">${card("l132","Lab 13.2","A Kubernetes StatefulSet",d=>`<h3>mongo-2 deleted: recreated and SECONDARY again in 32 s, 3 of 3 documents intact on its volume</h3>
    <table><tr><th>Check</th><th>Result</th></tr>${K8S.map(([c,x])=>`<tr><td>${c}${x?`<div class="meta">${x}</div>`:""}</td><td class="ok">PASS</td></tr>`).join("")}</table><p class="meta">9 of 9 checks passed</p>`,"A StatefulSet gives each member a stable name and its own volume, so Kubernetes heals a lost pod without losing its data.")}</div>
  </div>
  <p class="meta" style="margin-top:16px">Real runs: <code>lab3.1.py</code> (needs <code>docker compose -f docker-compose-production.yml up -d</code> and the hosts-file entry for mongo1, mongo2 and mongo3), the monitoring compose file, and <code>Lab 13.2 - Kubernetes StatefulSet for MongoDB.py</code> (Docker Desktop with Kubernetes enabled).</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};
/* ---- Operations: Deployment ---- */
const TSC={};
const series=(key,n,base,amp,ph,min=0)=>{const id=key+n;return TSC[id]||(TSC[id]=Array.from({length:n},(_,i)=>Math.max(min,base+amp*Math.sin(i/4+ph)+(Math.random()-.5)*amp*.4)))};
const LC=(ser,ymax,w=420,h=170,thr)=>{const L0=34,X=i=>L0+i/(ser[0].v.length-1)*(w-L0-8),Y=v=>h-20-v/ymax*(h-34);
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" role="img">${[0,.5,1].map(f=>`<line x1="${L0}" x2="${w-8}" y1="${Y(f*ymax)}" y2="${Y(f*ymax)}" style="stroke:var(--line)"/><text x="${L0-5}" y="${Y(f*ymax)+4}" text-anchor="end" font-size="10" style="fill:var(--mute)">${+(f*ymax).toFixed(2)}</text>`).join("")}
  ${ser.map(s=>`<polyline fill="none" stroke="${s.c}" stroke-width="2" points="${s.v.map((v,i)=>X(i)+","+Y(Math.min(v,ymax))).join(" ")}"/>`).join("")}${thr?`<line x1="${L0}" x2="${w-8}" y1="${Y(thr.v)}" y2="${Y(thr.v)}" stroke="#c2570a" stroke-dasharray="5 4"/><text x="${w-8}" y="${Y(thr.v)-4}" text-anchor="end" font-size="10" style="fill:var(--warn)">${thr.t}</text>`:""}</svg>
  <div class="row" style="gap:10px">${ser.map(s=>`<span class="meta"><span class="dot" style="background:${s.c}"></span>${s.n}</span>`).join("")}</div>`};
const timeRange=m=>{const e=new Date(),s=new Date(e-m*60000),f=d=>d.toTimeString().slice(0,5);return [f(s),f(e)]};
async function testFailover(){
  if(C13.busy)return;C13.busy=true;C13.msg="Stepping down the primary ...";redraw();
  const old=C13.m.find(m=>m.role=="PRIMARY");
  if(!DEMO){fetch(`${API}/replica/run/f13`,{method:"POST"}).catch(()=>{})}   // also runs the real step-down (lab3.1.py) in the background when the server is up
  await sleep(700);
  const nxt=C13.m.filter(m=>m!==old)[Math.floor(Math.random()*2)];
  old.role="SECONDARY";nxt.role="PRIMARY";C13.elections++;
  C13.segs.push({at:Math.min(.95,.5+.12*C13.segs.length),p:nxt.n});
  const secs=(1.2+Math.random()*1.4).toFixed(1);
  C13.audit.unshift({t:new Date().toLocaleTimeString(),u:ROLE=="Administrator"?"demo-admin":ROLE.toLowerCase(),a:"ops.failover",d:`${old.n} → ${nxt.n} in ${secs} s`});
  C13.msg=`New primary ${nxt.n} after ${secs} s`;C13.busy=false;redraw()}
const opsDeploy=function(){
  const R=C13.range,n=30,[t0,t1]=timeRange(R),pri=C13.m.find(m=>m.role=="PRIMARY"),canFo=ROLE=="Administrator";
  const rows=C13.m.map(m=>{let out="";C13.segs.forEach((s,i)=>{const end=(C13.segs[i+1]||{at:1}).at;out+=`<rect x="${s.at*100}%" width="${(end-s.at)*100}%" height="22" rx="3" style="fill:${s.p==m.n?"#2f6fd0":"#6a6ad9"}"><title>${m.n}: ${s.p==m.n?"PRIMARY":"SECONDARY"}</title></rect>`});return `<div class="row" style="gap:8px;flex-wrap:nowrap"><span class="mono meta" style="width:80px">${m.n}</span><svg width="100%" height="22">${out}</svg></div>`}).join("");
  const marks=C13.segs.slice(1).map(s=>`<span class="tag" style="border-color:var(--warn);color:var(--warn)">elected at ${Math.round(s.at*R)} min of ${R}</span>`).join("");
  const ops=series("o",n,11,1.2,0,0),q=series("q",n,.8,.5,1,0),ins=series("i",n,.5,.4,2,0);
  view.innerHTML=`<p class="meta">Administrators</p><h1>Operations</h1><p class="lead">Running this platform's data: the deployment and its failover, monitoring and backups.</p>
  <div class="row" id="opstabs" style="margin-bottom:12px"></div>
  <div class="labs"><div class="card"><b>Replica set rs0</b><p class="meta">Three members started with --auth and a shared keyfile: the same data on each, a new primary elected if one fails.</p>
    <div class="row">${C13.m.map(m=>`<span class="tag ${m.role=="PRIMARY"?"t-embed":""}">${m.n} ${m.role}</span>`).join("")}</div>
    <button id="fo" style="margin-top:12px;width:100%" ${canFo&&!C13.busy?"":"disabled"} ${canFo?"":'title="Administrators only"'}>⚡ Test failover</button><p class="meta" id="fomsg">${esc(C13.msg)}</p></div>
  <div class="card"><b>Kubernetes and Atlas</b><p class="meta">The StatefulSet of Lab 13.2 and the M0 cluster Terraform makes on Atlas.</p>
    <div class="grid" style="grid-template-columns:1fr 1fr">${stat("Kubernetes","mongo-0, mongo-1, mongo-2 Ready")}${stat("Last pod test","back in 32 s, data intact")}${stat("Atlas","not applied yet")}</div>
    <div class="row" style="margin-top:8px"><a class="tag" href="http://localhost:9090" target="_blank" rel="noopener">Prometheus ↗</a></div></div></div>
  <div class="card" style="margin-top:14px"><div class="row" style="justify-content:space-between"><b>Monitoring: the replica set over time</b><span class="row">${[15,30,60,360].map(m=>`<button class="alt ${m==R?"on":""}" data-r="${m}">${m>=60?m/60+" h":m+" min"}</button>`).join("")}</span></div>
  <p class="meta">Simulated here. With Prometheus connected, these come from the exporter every 15 s. Press Test failover and watch the primary move on the state timeline.</p>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">${stat("Primary now",pri.n)}${stat("Members up","3 of 3")}${stat("Operations",ops[n-1].toFixed(1)+"/s")}${stat("Replication lag","0.0 s")}${stat("Elections",C13.elections)}</div>
  <h2>Member states</h2><p class="meta">Which member was PRIMARY or SECONDARY at each moment; a change of colour is an election.</p>${rows}
  <div class="row" style="justify-content:space-between"><span class="meta mono">${t0}</span><span class="row">${marks}</span><span class="meta mono">${t1}</span></div>
  <div class="split" style="margin-top:12px"><div><h2>Operations per second</h2>${LC([{n:"command",c:"#2f6fd0",v:ops},{n:"query",c:"#c2417a",v:q},{n:"insert",c:"#4d7c0f",v:ins}],15)}</div>
  <div><h2>Replication lag (s)</h2>${LC(C13.m.map(m=>({n:m.n,c:C13COL[m.n],v:Array(n).fill(0)})),1)}</div>
  <div><h2>Heartbeat ping (ms)</h2>${LC([{n:"lab13-rs2",c:"#c2417a",v:series("p2",n,1,.6,0,0)},{n:"lab13-rs3",c:"#4d7c0f",v:series("p3",n,.8,.4,1,0)}],8)}</div>
  <div><h2>Connections</h2>${LC([{n:"connections",c:"#2f6fd0",v:series("c",n,24,1,0,0)}],30)}</div>
  <div><h2>WiredTiger cache in use (MiB)</h2>${LC([{n:"cache",c:"#6a6ad9",v:series("w",n,.8,.02,0,0)}],1)}<p class="meta">Capped at 256 MiB per member (--wiredTigerCacheSizeGB 0.25).</p></div></div></div>
  <div class="card"><b>Audit log</b>${C13.audit.length?`<table><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th></tr>${C13.audit.map(a=>`<tr><td class="mono">${a.t}</td><td>${a.u}</td><td class="mono">${a.a}</td><td>${esc(a.d)}</td></tr>`).join("")}</table>`:'<p class="meta">No failovers yet. Test failover writes an <code>ops.failover</code> entry here.</p>'}</div>`;
  $("#fo")&&($("#fo").onclick=testFailover);
  view.querySelectorAll("[data-r]").forEach(b=>b.onclick=()=>{C13.range=+b.dataset.r;redraw()});
};

/* ===== Chapter 14: monitoring and backup, Operations > Monitoring & backups, Moderation > Alerts =====
   Lab results are your recorded runs. The Operations charts are simulated unless the monitor feeds real samples. */
["l141","a141","l142"].forEach(k=>LAB[k]={st:"idle",log:[],d:null,open:false});
let OPSTAB="deploy";
const C14={range:30,backups:[{n:"20261115_160717",mb:.13}],verify:null,alerts:[
 {id:1,t:"15 Nov, 15:19",k:"cache_hit_ratio",x:"cache hit ratio 42.0% is below 80% (simulated)",ack:false},
 {id:2,t:"15 Nov, 14:53",k:"cache_hit_ratio",x:"cache hit ratio 97.0% is below 100%",ack:false}],nid:3,busy:""};
const nowS=()=>new Date().toLocaleTimeString(),audit=(a,d)=>C13.audit.unshift({t:nowS(),u:ROLE=="Administrator"?"demo-admin":ROLE.toLowerCase(),a,d});
Object.assign(runs,{
async l141(){for(const t of["Monitoring mongodb://... every 30 s, logging to metrics.log","serverStatus: connections 23, cache 0.5 of 256 MB, hit ratio 97.0%","replSetGetStatus: mongo1 SECONDARY, mongo2 PRIMARY, mongo3 SECONDARY, lag 0.0 s","WARNING: cache hit ratio 97.0% is below 100%","Log written to metrics.log"]){await sleep(420);L("l141",t)}LAB.l141.d={}},
async a141(){for(const t of["Local test receiver listening, webhook format: generic","Sample 1: WARNING cache hit ratio 42.0% (simulated) -> webhook alert (1): sent, HTTP 200","Sample 2: alert still active -> not re-sent (cooldown 300 s)","Sample 3: No alerts -> webhook resolved (1): sent, HTTP 200","Sample 4: No alerts"]){await sleep(420);L("a141",t)}LAB.a141.d={}},
async l142(){for(const t of["1) Inserted 1000 test documents (verified=True)","2) mongodump backup taken (0.08 s)","3) Modified 1000 documents (verified=False)","4) mongorestore --drop (0.48 s)","5) PASS: 1000 documents recovered, all fields match","6) Retention: 8-day-old demo backup removed","RESULT: restore verified"]){await sleep(420);L("l142",t)}LAB.l142.d={}}
});
const R14=[["Inserted 1,000 documents into chapter-14.backup_test","verified = True"],["Backup (mongodump, one namespace)","0.08 s"],["Modified every document","verified = False"],["Restore (mongorestore --drop)","0.48 s"],["Compared every document with the original","PASS: 1,000 recovered, all fields match"],["Retention: an 8-day-old demo backup was removed","True"]];
const A14=[["1","cache hit ratio 42.0% below 80% (simulated)","webhook alert (1): sent, HTTP 200"],["2","same alert still active","not re-sent (cooldown 300 s)"],["3","No alerts","webhook resolved (1): sent, HTTP 200"],["4","No alerts","nothing to send"]];
const bk=(a)=>{const s=C14.backups.length;return s};
pages.mon=function(){
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 14: monitoring and backup</p>
  <div class="rs-head"><div><h1>Chapter 14: monitoring and backup</h1><p class="lead">Chapter 7's data watched and backed up: the metrics a DBA reads, alerts when the cache or replication falls behind, and backups whose restore is checked document by document.</p><span class="badge passed">Lab results shown are your recorded runs</span></div>
  <div class="card"><b>Replica set</b><div class="members" style="margin-top:8px">${[["mongo1","SECONDARY"],["mongo2","PRIMARY"],["mongo3","SECONDARY"]].map(([n,r])=>`<div class="mem ${r}"><small>${r}</small><span class="dot" style="background:${r=="PRIMARY"?"#2f6fd0":"#6a6ad9"}"></span>${n}</div>`).join("")}</div></div></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Data used</b><code>chapter-14 database</code></div>
  <div class="row"><div class="card" style="margin:0"><code>events</code> <span class="meta">written by the demo traffic of Lab 14.1</span></div><div class="card" style="margin:0"><span class="stat">1,000</span> <code>backup_test</code> <span class="meta">Lab 14.2</span></div></div></div>
  <h2>Live from the lab</h2><div class="labs">
  <div class="card"><b>Live metrics (monitor, every 30 s)</b><p class="meta">A WARNING is raised under 80 % cache hits or over 10 s of lag. Sample of 15 Nov, 15:19.</p>
    <div class="grid" style="grid-template-columns:1fr 1fr">${stat("Connections","23 current")}${stat("Cache hit ratio","99.2 %")}${stat("Operations per second","getmore 0.7, command 5.0")}${stat("Cache","0.6 of 256 MB")}</div></div>
  <div class="card"><b>Alerts received (the webhook receiver)</b><p class="meta">Every alert is posted as JSON; Activity 14.1 also formats them for Slack or Discord.</p>
    ${C14.alerts.slice(0,4).map(a=>`<div style="margin:6px 0"><span class="badge" style="color:#b42318;border-color:#b42318">WARNING</span> ${esc(a.x)} <span class="meta">${a.t}</span></div>`).join("")}<a class="tag" href="#mod">Moderation alerts</a></div>
  <div class="card"><b>Backups</b><p class="meta">mongodump into a folder named by its time; folders older than 7 days are deleted.</p>
    ${C14.backups.slice(0,5).map(b=>`<div class="mono" style="margin:4px 0">backup_${b.n} <span class="meta">${b.mb.toFixed(2)} MB</span></div>`).join("")}<a class="tag" href="#ops" onclick="OPSTAB='mon'">Back up now (Operations)</a></div>
  <div class="card"><b>Restore check, RPO and RTO (Lab 14.2)</b><p class="meta">A backup counts once its restore is verified. RPO: how much data can be lost; RTO: how long recovery takes.</p>
    <div class="grid" style="grid-template-columns:1fr 1fr 1fr">${stat("Restore verified","every document identical")}${stat("RPO","1 h (the backup interval)")}${stat("RTO","restore 0.48 s + restart")}</div>
    <p class="meta">RTO = restore time + application restart time (the script assumes 30 s: 0.48 s + 30 s = 30.48 s for 1,000 documents).</p></div></div>
  <h2>Labs</h2><div class="labs">
  ${card("l141","Lab 14.1","A monitoring dashboard with threshold alerts",d=>`<h3>cache hit ratio 97.0% fell under the 100% threshold: WARNING raised</h3>
    <table><tr><th>Metric</th><th>Value</th></tr><tr><td>Connections (current / active / total created)</td><td class="mono">23 / 7 / 199</td></tr><tr><td>Cache used</td><td class="mono">0.5 of 256 MB</td></tr><tr><td>Pages requested / read in</td><td class="mono">2,894 / 88</td></tr><tr><td>Replica set</td><td>mongo2 PRIMARY, others SECONDARY, lag 0.0 s</td></tr></table>
    <p class="bad">WARNING: cache hit ratio 97.0% is below 100%</p><p class="meta">The lag threshold of 0 raised nothing because the lag was 0.0 s.</p>`,"serverStatus and replSetGetStatus show the cache and replication falling behind before users notice, and thresholds turn that into alerts.")}
  ${card("a141","Activity 14.1","Alerts to a webhook",d=>`<h3>1 alert posted to the webhook receiver, cooled down, then resolved</h3>
    <table><tr><th>Sample</th><th>State</th><th>Webhook</th></tr>${A14.map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td></tr>`).join("")}</table>
    <div class="row" style="margin-top:6px"><span class="tag">Slack {"text"}</span><span class="tag">Discord {"content"}</span><span class="tag">generic JSON</span></div>`,"Alerts leave the monitor as JSON webhooks inside try/except, so a dead receiver cannot stop the monitor.")}
  <div style="grid-column:1/-1">${card("l142","Lab 14.2","Backups, restore verification, RPO and RTO",d=>`<h3>restore verified: 1,000 of 1,000 documents; backup 0.08 s, restore 0.48 s</h3>
    <table><tr><th>Step</th><th>Result</th></tr>${R14.map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td></tr>`).join("")}</table>
    <p class="meta">Benchmark mode (1,000 / 10,000 / 100,000 documents) was not in your recorded run. Run <code>--benchmark</code> to fill that table.</p>`,"A backup counts only once its restore is checked: RPO is the backup interval, RTO the measured restore plus the restart.")}</div></div>
  <p class="meta" style="margin-top:16px">Real runs: <code>Lab 14.1 - Build a Monitoring Dashboard.py</code>, <code>Activity for 14.1 - Try it yourself.py</code> and <code>Lab 14.2 - Automated Backup and Restore Verification.py</code> (needs the MongoDB Database Tools on PATH and the Chapter 13 replica set running).</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};
/* ---- Operations tab: Monitoring & backups ---- */
async function opsAction(kind){
  if(C14.busy)return;C14.busy=kind;redraw();
  if(!DEMO){fetch(`${API}/replica/run/${kind=="backup"?"b14":"v14"}`,{method:"POST"}).catch(()=>{})}   // real mongodump / restore check in the background
  await sleep(900);
  if(kind=="backup"){const d=new Date(),p=n=>String(n).padStart(2,"0"),name=`${d.getFullYear()}${p(d.getMonth()+1)}${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
    C14.backups.unshift({n:name,mb:+(.12+Math.random()*.03).toFixed(2)});audit("ops.backup","backup_"+name)}
  else{C14.verify={docs:1000,restore:+(0.4+Math.random()*.2).toFixed(2)};audit("ops.verify",`restore verified: 1000 of 1000 documents, restore ${C14.verify.restore} s`)}
  C14.busy="";redraw()}
const opsMon=function(){
  const R=C14.range,n=30,canOp=ROLE=="Administrator",nb=C14.backups[0],[t0,t1]=timeRange(R),ver=C14.verify;
  const hit=series("h"+R,n,99.4,.4,0,0),lag=series("l"+R,n,.3,.3,1,0),ops=series("m"+R,n,6,2,0,0),cn=series("k"+R,n,22,1.2,0,0);
  const open=C14.alerts.filter(a=>!a.ack).length,rto=ver?(ver.restore+30).toFixed(1)+" s":"30.5 s";
  const bars=C14.backups.slice(0,10).reverse(),mx=Math.max(.3,...bars.map(b=>b.mb))*1.2;
  view.innerHTML=`<p class="meta">Administrators</p><h1>Operations</h1><p class="lead">Running this platform's data: the deployment and its failover, monitoring and backups.</p>
  <div class="row" id="opstabs" style="margin-bottom:12px"></div>
  <div class="labs"><div class="card"><b>Live metrics</b><p class="meta">The newest sample of Chapter 14's monitor (every 30 s): a WARNING goes to the moderators' alert list when the cache hit ratio falls under 80 % or lag passes 10 s.</p>
    <div class="row">${[["mongo1","SECONDARY"],["mongo2","PRIMARY"],["mongo3","SECONDARY"]].map(([x,r])=>`<span class="tag ${r=="PRIMARY"?"t-embed":""}">${x} ${r}</span>`).join("")}</div>
    <div class="grid" style="grid-template-columns:1fr 1fr;margin-top:8px">${stat("Connections",Math.round(cn[n-1]))}${stat("Cache hit ratio",hit[n-1].toFixed(1)+" %")}${stat("Cache","0.6 of 256 MB")}</div></div>
  <div class="card"><b>Backups</b><p class="meta">mongodump every hour, kept 7 days. Verify restore loads the newest backup into a scratch database and compares every document with the live one.</p>
    <div class="grid" style="grid-template-columns:1fr 1fr">${stat("Newest","backup_"+nb.n)}${stat("Kept",C14.backups.length+" backups")}${stat("RPO","1 h")}${stat("RTO",rto+" (restore + restart)")}</div>
    <div class="row" style="margin-top:10px"><button id="bk" style="flex:1" ${canOp&&!C14.busy?"":"disabled"} ${canOp?"":'title="Administrators only"'}>${C14.busy=="backup"?"Backing up …":"Back up now"}</button><button id="vr" style="flex:1" ${canOp&&!C14.busy?"":"disabled"} ${canOp?"":'title="Administrators only"'}>${C14.busy=="verify"?"Verifying …":"Verify restore"}</button></div>
    ${ver?`<p class="ok">Restore verified: ${ver.docs} of ${ver.docs} documents identical, restore ${ver.restore} s.</p>`:""}</div></div>
  <div class="card" style="margin-top:14px"><div class="row" style="justify-content:space-between"><b>Monitoring: Chapter 14's monitor over time</b><span class="row">${[30,120,720].map(m=>`<button class="alt ${m==R?"on":""}" data-r="${m}">${m>=60?m/60+" h":m+" min"}</button>`).join("")}</span></div>
  <p class="meta">Simulated here; with the monitor feeding MongoDB these are its real samples, with the thresholds that raise a WARNING.</p>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">${stat("Cache hit ratio",hit[n-1].toFixed(1)+" %")}${stat("Replication lag",lag[n-1].toFixed(1)+" s")}${stat("Alerts raised",open+" open")}${stat("Newest backup","backup_"+nb.n.slice(9,13))}${stat("Restore (RTO)",rto)}</div>
  <div class="split" style="margin-top:12px"><div><h2>Cache hit ratio (%)</h2>${LC([{n:"lab14-rs1",c:"#2f6fd0",v:hit}],100,420,170,{v:80,t:"WARNING under 80 %"})}</div>
  <div><h2>Replication lag (s)</h2>${LC([{n:"mongo1",c:"#c2417a",v:lag},{n:"mongo3",c:"#4d7c0f",v:lag.map(x=>x*.6)}],12,420,170,{v:10,t:"WARNING over 10 s"})}</div>
  <div><h2>Operations per second</h2>${LC([{n:"command",c:"#2f6fd0",v:ops},{n:"getmore",c:"#6a6ad9",v:ops.map(x=>x*.3)}],15)}</div>
  <div><h2>Connections</h2>${LC([{n:"connections",c:"#2f6fd0",v:cn}],30)}</div></div>
  <h2>Backups kept</h2><p class="meta">Each mongodump of the last runs, by size (MB): hourly, and every Back up now.</p>
  <svg viewBox="0 0 640 140" width="100%" role="img" aria-label="Backups kept by size">${bars.map((b,i)=>{const w=640/Math.max(bars.length,1),h=b.mb/mx*100;return `<rect x="${i*w+w*.2}" y="${120-h}" width="${w*.6}" height="${h}" rx="3" style="fill:var(--acc)"><title>backup_${b.n}: ${b.mb} MB</title></rect><text x="${i*w+w/2}" y="136" text-anchor="middle" font-size="10" style="fill:var(--mute)">${b.n.slice(4,6)}/${b.n.slice(6,8)} ${b.n.slice(9,11)}:${b.n.slice(11,13)}</text>`}).join("")}</svg></div>
  <div class="card"><b>Audit log</b>${C13.audit.length?`<table><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th></tr>${C13.audit.map(a=>`<tr><td class="mono">${a.t}</td><td>${a.u}</td><td class="mono">${a.a}</td><td>${esc(a.d)}</td></tr>`).join("")}</table>`:'<p class="meta">Back up now and Verify restore write <code>ops.backup</code> and <code>ops.verify</code> entries here.</p>'}</div>`;
  $("#bk")&&($("#bk").onclick=()=>opsAction("backup"));$("#vr")&&($("#vr").onclick=()=>opsAction("verify"));
  view.querySelectorAll("[data-r]").forEach(b=>b.onclick=()=>{C14.range=+b.dataset.r;redraw()});
};
pages.ops=function(a){
  if(a)OPSTAB=a;
  OPSTAB=="mon"?opsMon():OPSTAB=="orgs"?opsOrgs():OPSTAB=="audit"?opsAudit():OPSTAB=="ask"?opsAsk():OPSTAB=="sources"?opsSources():opsDeploy();
  const t=$("#opstabs");if(t){t.innerHTML=[["deploy","Deployment","Ch 13"],["mon","Monitoring & backups","Ch 14"],["orgs","Organisations","Ch 15"],["audit","Audit log","Ch 16"],["ask","Ask index","Ch 17"],["sources","Sources","Ch 18"]].map(([k,n,c])=>`<button class="alt ${OPSTAB==k?"on":""}" data-t="${k}">${n} <span class="meta">${c}</span></button>`).join("")+"";
    t.querySelectorAll("[data-t]").forEach(b=>b.onclick=()=>{OPSTAB=b.dataset.t;redraw()})}
};
/* ---- Moderation: tab strip shared by Alerts (Ch 14) and Fraud review (Ch 16) ---- */
let MODTAB="alerts";
const modTabs=()=>{const t=$("#modtabs");if(!t)return;
  t.innerHTML=[["fp","False positives","Ch 18"],["fraud","Fraud review","Ch 16"],["alerts","Alerts","Ch 14"],["orgs","Organisations","Ch 15"]].map(([k,n,c])=>`<button class="alt ${MODTAB==k?"on":""}" data-m="${k}">${n} <span class="meta">${c}</span></button>`).join("")+"";
  t.querySelectorAll("[data-m]").forEach(b=>b.onclick=()=>{MODTAB=b.dataset.m;redraw()})};
/* ---- Moderation > Alerts ---- */
const modAlerts=function(){
  const canAck=ROLE!="Client",open=C14.alerts.filter(a=>!a.ack).length;
  view.innerHTML=`<p class="meta">Moderators and admins</p><h1>Moderation</h1><p class="lead">The reviews that keep this platform's data trustworthy: indicators that may be false positives, suspicious billing accounts, monitoring alerts and the organisations' activity.</p>
  <div class="row" id="modtabs" style="margin-bottom:12px"></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Monitoring alerts</b><button class="alt" id="ta" ${ROLE=="Administrator"?"":"disabled"}>Raise test alert</button></div>
  <p class="meta">Warnings Chapter 14's monitor raised about its replica set: a cache hit ratio under 80 % or replication lag over 10 seconds, delivered to the webhook receiver. Acknowledge one when it has been looked at.</p>
  <p><b>${open}</b> not acknowledged</p>
  ${C14.alerts.map(a=>`<div class="card" style="margin:8px 0;${a.ack?"opacity:.55":""}"><div class="row" style="justify-content:space-between"><span><span class="badge" style="color:#b42318;border-color:#b42318">WARNING</span> ${esc(a.x)}<div class="meta">${a.t} · ${a.k}</div></span>${a.ack?'<span class="badge passed">Acknowledged</span>':`<button class="alt" data-ack="${a.id}" ${canAck?"":'disabled title="Clients cannot acknowledge alerts"'}>Acknowledge</button>`}</div></div>`).join("")||'<p class="meta">No alerts.</p>'}</div>`;
  view.querySelectorAll("[data-ack]").forEach(b=>b.onclick=()=>{const a=C14.alerts.find(x=>x.id==+b.dataset.ack);a.ack=true;audit("alert.ack",a.x);redraw()});
  $("#ta")&&($("#ta").onclick=()=>{const lag=Math.random()<.5,x=lag?`replication lag of mongo3:27037 is ${(10+Math.random()*50).toFixed(1)} s (more than 10 s)`:`cache hit ratio ${(55+Math.random()*20).toFixed(1)}% is below 80%`;
    C14.alerts.unshift({id:C14.nid++,t:new Date().toLocaleString("en-GB",{day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"}),k:lag?"replication_lag_s":"cache_hit_ratio",x,ack:false});redraw()});
};

/* ===== Chapter 15: multi-tenant cases (Chapter 15 page, Cases page, Operations > Organisations, Moderation > Organisations) =====
   Lab results are your recorded runs. The organisations and cases below are simulated; the lab scripts use their own
   'tasktracker' and 'chapter-15' databases. */
["l151","a151","l152"].forEach(k=>LAB[k]={st:"idle",log:[],d:null,open:false});
Object.assign(runs,{
async l151(){for(const t of["1) Login and JWT claims: bob's token carries tenant_id=acme, role=user; wrong password -> HTTP 401","3) Tenant isolation: acme sees only its 3 tasks, globex only its 1; cross-tenant read/update/delete -> HTTP 404","5) Role check: regular user cannot list users -> HTTP 403","6) Rate limiting: status codes [200, 200, 200, 200, 200, 429, 429]; Retry-After header present","7) Indexes: (tenant_id, created_at), (tenant_id, owner_id), unique (tenant_id, username), TTL on rate_limits.ts","RESULT: 25 passed, 0 failed"]){await sleep(380);L("l151",t)}LAB.l151.d={}},
async a151(){for(const t of["2) bob lists 2 task(s) (own tasks only); alice lists 3 (admin: every acme task)","3) bob cannot read, update or delete carol's task -> HTTP 403","4) bob can update and delete his own task -> HTTP 200","5) admin alice can read, update and delete carol's task","6) admin alice cannot read or delete a globex task -> HTTP 404","RESULT: 18 passed, 0 failed"]){await sleep(380);L("a151",t)}LAB.a151.d={}},
async l152(){for(const t of["1) Seeding document-level isolation: 5 tenants x 100 tasks = 500 documents","2) Migrating to collection-per-tenant: acme 100 documents (265 ms), globex 100 (246 ms), ...","3) Validating: counts match, no foreign documents, documents identical -> RESULT: 17 passed, 0 failed","4) Benchmark: list one tenant's tasks 1.286 ms vs 1.209 ms, create 6.208 ms vs 6.597 ms","   analytics result identical for both strategies: True","5) Recommendation printed"]){await sleep(380);L("l152",t)}LAB.l152.d={}}
});
const ORG15=[["Aurora SOC","aurora-soc","custom",4,3,10],["Bluefin CSIRT","bluefin-csirt","standard",2,1,8],["Cobalt CERT","cobalt-cert","standard",2,1,14],["DeltaGuard Incident Response","deltaguard-ir","custom",2,1,8],["Ember Security Labs","ember-labs","standard",2,1,8]];
const ST15=["open","in_progress","closed"],MEM15=["analyst1","analyst2"];
const CASES15=ORG15.map((o,oi)=>Array.from({length:o[5]},(_,k)=>({id:`${o[1]}-${String(k+1).padStart(3,"0")}`,t:`${ACTORS[(oi*3+k)%ACTORS.length][0]} activity`,s:ST15[(k+oi)%3],own:MEM15[k%2]})));
const C15={org:"",role:"admin",sent:0,refused:3};
const LIMIT15=30;
const o15=()=>({orgs:ORG15.length,mem:ORG15.reduce((s,o)=>s+o[3],0),cases:ORG15.reduce((s,o)=>s+o[5],0)});
const bars15=(rows,color)=>{const mx=Math.max(1,...rows.map(r=>r[1]));return rows.map(([n,v])=>`<div class="bars" style="grid-template-columns:170px 1fr 40px"><span>${esc(n)}</span><div class="bar"><i style="width:${v/mx*100}%;background:${color}"></i></div><span class="mono">${v}</span></div>`).join("")};
const orgsHtml=()=>{const t=o15();return `<div class="card"><b>Organisations</b><p class="meta">The tenants of the Chapter 15 case service: members on this platform and how many cases each organisation holds. Counts only: a case's contents stay with its organisation. Simulated here.</p>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">${stat("Organisations",t.orgs)}${stat("Members",t.mem)}${stat("Cases",t.cases)}${stat("Refused by the rate limit",C15.refused+" requests so far")}</div>
  <div class="split" style="margin-top:12px"><div><h2>Cases per organisation</h2><p class="meta">Each tenant's cases in the Chapter 15 service: isolated by tenant_id on every query.</p>${bars15(ORG15.slice().sort((a,b)=>b[5]-a[5]).map(o=>[o[0],o[5]]),"var(--acc)")}</div>
  <div><h2>Members per organisation</h2><p class="meta">Accounts on this platform that belong to each organisation.</p>${bars15(ORG15.slice().sort((a,b)=>b[3]-a[3]).map(o=>[o[0],o[3]]),"var(--acc)")}</div></div>
  <table style="margin-top:12px"><tr><th>Organisation</th><th>Tenant</th><th>Members</th><th>Org admins</th><th>Cases</th></tr>${ORG15.slice().sort((a,b)=>a[0].localeCompare(b[0])).map(o=>`<tr><td>${esc(o[0])}</td><td class="mono">${o[1]}</td><td>${o[3]}</td><td>${o[4]}</td><td>${o[5]}</td></tr>`).join("")}</table>
  <p class="meta">${C15.refused} requests refused by the rate limit so far.</p></div>`};
const opsOrgs=function(){
  view.innerHTML=`<p class="meta">Administrators</p><h1>Operations</h1><p class="lead">Running this platform's data: the deployment and its failover, monitoring and backups, organisations and the audit trail.</p>
  <div class="row" id="opstabs" style="margin-bottom:12px"></div>${orgsHtml()}`};
const modOrgs=function(){
  view.innerHTML=`<p class="meta">Moderators and admins</p><h1>Moderation</h1><p class="lead">The reviews that keep this platform's data trustworthy: indicators that may be false positives, suspicious billing accounts, monitoring alerts and the organisations' activity.</p>
  <div class="row" id="modtabs" style="margin-bottom:12px"></div>${orgsHtml()}`};
/* ---- Cases (member view of the multi-tenant service) ---- */
pages.cases=function(){
  const oi=ORG15.findIndex(o=>o[1]==C15.org),admin=C15.role=="admin";
  const all=oi<0?[]:CASES15[oi],mine=admin?all:all.filter(c=>c.own==MEM15[0]);
  view.innerHTML=`<p class="meta">Chapter 15 · lab15</p><h1>Cases</h1><p class="lead">Your organisation's investigation cases on the threats and events of this platform, kept by a multi-tenant case service: each organisation sees only its own cases.</p>
  <div class="card"><div class="row"><label class="row">Your account belongs to <select id="co"><option value="">no organisation</option>${ORG15.map(o=>`<option value="${o[1]}" ${o[1]==C15.org?"selected":""}>${esc(o[0])}</option>`).join("")}</select></label>
  <label class="row">as <select id="cr"><option value="admin" ${admin?"selected":""}>organisation admin</option><option value="member" ${admin?"":"selected"}>member (${MEM15[0]})</option></select></label></div>
  <p class="meta">Demo controls: in the real service the organisation and role come from the signed token, never from the browser.</p></div>
  ${oi<0?`<div class="card"><b>No organisation yet</b><p>Your account is not in an organisation yet. Ask an administrator to add you to one (Admin, Users), then open Cases again.</p></div>`
  :`<div class="card"><div class="row" style="justify-content:space-between"><b>${esc(ORG15[oi][0])}</b><span class="meta">tenant_id = ${ORG15[oi][1]} · ${admin?"admin: every case of the tenant":"member: own cases only"}</span></div>
  <p><b>${mine.length}</b> of ${all.length} cases shown</p>
  <table><tr><th>Case</th><th>Title</th><th>Status</th><th>Owner</th></tr>${mine.map(c=>`<tr><td class="mono">${c.id}</td><td>${esc(c.t)}</td><td>${c.s}</td><td>${c.own}</td></tr>`).join("")}</table>
  <div class="row" style="margin-top:10px"><button class="alt" id="cs">Send ${LIMIT15+5} requests in a minute</button><span class="meta">Rate limit: ${LIMIT15} requests a minute per user (counter in MongoDB). ${C15.sent?`Last burst: ${Math.min(C15.sent,LIMIT15)} accepted, ${Math.max(0,C15.sent-LIMIT15)} refused with HTTP 429 and a Retry-After header.`:""}</span></div></div>`}`;
  $("#co").onchange=e=>{C15.org=e.target.value;redraw()};$("#cr").onchange=e=>{C15.role=e.target.value;redraw()};
  $("#cs")&&($("#cs").onclick=()=>{C15.sent=LIMIT15+5;C15.refused+=5;audit("cases.rate_limited",`${ORG15[oi][1]}: 5 requests refused (HTTP 429)`);redraw()});
};
/* ---- Chapter 15 page ---- */
const T15=[["Isolation: acme sees its 3 tasks, globex its 1; another tenant's task by id","HTTP 404 on read, update and delete"],["Login: token carries tenant_id and role; wrong password","tenant_id=acme, role=user; HTTP 401"],["CRUD inside one tenant","read, update, delete, then 404"],["Role check in an endpoint","regular user lists users: HTTP 403; admin sees only her own tenant"],["Rate limit set to 5 per 60 s for the test","[200, 200, 200, 200, 200, 429, 429]; Retry-After set; globex unaffected"],["Indexes","(tenant_id, created_at), (tenant_id, owner_id), unique (tenant_id, username), TTL on rate_limits.ts"]];
const R15=[["bob lists his own tasks","2 tasks"],["carol lists her own task","1 task"],["admin alice lists the tenant","3 tasks"],["bob reads, updates or deletes carol's task","HTTP 403 each"],["bob updates and deletes his own task","HTTP 200"],["admin alice reads, updates, deletes carol's task","HTTP 200"],["admin alice reads a globex task","HTTP 404"]];
const M15=[["List one tenant's tasks (sorted)","1.286","1.209","59.286","56.373"],["Create a task","6.208","6.597","5.359","5.652"],["Cross-tenant analytics","1.739","1.751","68.833","65.284"]];
pages.tenants=function(){
  const t=o15(),st={};CASES15.flat().forEach(c=>st[c.s]=(st[c.s]||0)+1);
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 15: multi-tenant cases</p>
  <div class="rs-head"><div><h1>Chapter 15: multi-tenant cases</h1><p class="lead">Chapter 7's threats become organisations' investigation cases: every query carries the tenant from a signed token, each role manages only what it should, and a busy user is slowed by a rate limit kept in MongoDB.</p><span class="badge passed">Lab results shown are your recorded runs</span></div>
  <div class="card"><b>Case service</b><div class="members" style="margin-top:8px">${[["API, 5 TENANTS","FastAPI :8000"],["MONGODB","tasktracker"]].map(([r,n])=>`<div class="mem"><small>${r}</small>${n}</div>`).join("")}</div></div></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Data used</b><code>tasktracker database</code></div>
  <p>Organisations (tenants), their members and cases; every document carries a tenant_id</p>
  <div class="row"><div class="card" style="margin:0"><span class="stat">${t.cases}</span> <code>cases</code> <span class="meta">simulated, per tenant</span></div><div class="card" style="margin:0"><span class="stat">${t.mem}</span> <code>users</code> <span class="meta">members of the organisations</span></div><div class="card" style="margin:0"><span class="stat">${t.orgs}</span> <code>tenants</code></div></div></div>
  <h2>Live from the lab</h2><div class="labs">
  <div class="card"><b>Tenants and their cases</b><p class="meta">Each organisation is a tenant: its cases sit in one shared collection, always queried with its tenant_id.</p>
    <table><tr><th>Organisation</th><th>Plan</th><th>Cases</th></tr>${ORG15.map(o=>`<tr><td>${esc(o[0])} <span class="meta mono">${o[1]}</span></td><td>${o[2]}</td><td>${o[5]}</td></tr>`).join("")}</table>
    <p class="meta">By status: ${ST15.map(s=>s+" "+(st[s]||0)).join(", ")}. Open the <a href="#cases">Cases page</a> as a member of one.</p></div>
  <div class="card"><b>Signed tokens and the rate limit</b><p class="meta">The token carries tenant_id and role; a counter per tenant in MongoDB (with a TTL index) counts each request window.</p>
    <div class="grid" style="grid-template-columns:1fr 1fr">${stat("Lab default limit","100 requests per tenant per 60 s")}${stat("Refused so far",C15.refused+" requests")}</div></div>
  <div class="card"><b>Isolation strategies compared (Lab 15.2)</b><p class="meta">The same tasks in one shared collection and in a collection per tenant: median ms of 200 runs (500 documents | 100,000 documents).</p>
    <table><tr><th>Operation</th><th>Shared</th><th>Per tenant</th><th>Shared (100k)</th><th>Per tenant (100k)</th></tr>${M15.map(r=>`<tr><td>${r[0]}</td>${r.slice(1).map(x=>`<td class="mono">${x}</td>`).join("")}</tr>`).join("")}</table>
    <p class="meta">5 of 5 tenants migrated with equal documents, 0 documents of another tenant in a tenant collection.</p></div></div>
  <h2>Labs</h2><div class="labs">
  ${card("l151","Lab 15.1","A multi-tenant API",d=>`<h3>25 checks pass: another tenant's task answered 404; 2 of 7 requests refused by the rate limit</h3>
    <table><tr><th>Check</th><th>Result</th></tr>${T15.map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td></tr>`).join("")}</table>`,"tenant_id from a signed token in every query isolates the tenants of one collection, and a counter document rate-limits each tenant.")}
  ${card("a151","Activity 15.1","Role-based access control",d=>`<h3>18 checks pass: admin manages the whole tenant, a member only their own tasks</h3>
    <table><tr><th>Who does what</th><th>Result</th></tr>${R15.map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td></tr>`).join("")}</table>`,"The role in the token decides: admins manage every task of their tenant, members only their own, and nobody crosses a tenant.")}
  <div style="grid-column:1/-1">${card("l152","Lab 15.2","Migrating between tenant isolation strategies",d=>`<h3>5 of 5 tenants moved to their own collections, 17 checks pass; no clear winner at this size</h3>
    <table><tr><th>Tenant</th><th>Collection</th><th>Documents</th><th>Time</th></tr>${[["acme",265],["globex",246],["initech",234],["umbrella",237],["hooli",303]].map(([t,ms])=>`<tr><td>${t}</td><td class="mono">tasks_tenant_${t}</td><td>100</td><td>${ms} ms</td></tr>`).join("")}</table>
    <p class="meta">Analytics gave the same answer with $group on one collection and with $unionWith across the tenant collections. Benchmark: see the comparison above.</p>`,"$match + $out moves a tenant out of the shared collection safely; per-tenant collections suit single-tenant work and backups, one shared collection suits cross-tenant analytics.")}</div></div>
  <p class="meta" style="margin-top:16px">Real runs: <code>Lab 15.1 - Design a Multi-Tenant API.py</code>, <code>Activity for 15.1 - Try it yourself.py</code> and <code>Lab 15.2 - Data Migration Between Tenant Isolation Strategies.py</code> (pip install fastapi uvicorn pymongo pyjwt httpx python-dotenv; set <code>CH15_URI</code> before starting server.py if your MongoDB is not on 27047).</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};

/* ===== Chapter 16: Cassandra and Neo4j (Chapter 16 page, Operations > Audit log, Moderation > Fraud review) =====
   Lab results are your recorded runs. Cassandra and Neo4j are simulated in memory by the lab scripts, so the audit log
   and the fraud review below are simulated too; MongoDB is the real server when server.py is running. */
["l161","a161","l162"].forEach(k=>LAB[k]={st:"idle",log:[],d:null,open:false});
Object.assign(runs,{
async l161(){for(const t of["1) MongoDB: document model (real server)","   [PASS] MongoDB Q1 courses of Alice -> ['C1', 'C2']","   [PASS] MongoDB Q2 students in C1 -> ['Alice', 'Bob']","   [PASS] MongoDB Q3 students sharing a course with Alice -> ['Bob', 'Carol']","2) Cassandra: query-driven tables (simulated). Q3 needed 3 partition reads and an application-side merge","3) Neo4j: Q3 in one MATCH pattern (simulated)","4) Same answers in all three models","RESULT: 12 passed, 0 failed"]){await sleep(380);L("l161",t)}LAB.l161.d={}},
async a161(){for(const t of["2) CS301 needs CS101 and CS201 (indirect prerequisite found)","3) Alice cannot enroll in CS301 without prerequisites -> missing ['CS101', 'CS201']","3) after completing CS101 and CS201 she can enroll in CS301","4) events wait in the MongoDB outbox before the worker runs -> 2 pending","4) worker moves all events to the audit table -> 2 event(s) moved","4) newest event is returned first -> ['ENROLLED', 'ENROLL_REJECTED']","RESULT: 10 passed, 0 failed"]){await sleep(380);L("a161",t)}LAB.a161.d={}},
async l162(){for(const t of["Circuit breaker: 3 consecutive failures -> backend skipped, retry after 30 s","1) Unit tests (unittest.mock): RESULT: 9 passed, 0 failed","2) Integration test, full fraud workflow: RESULT: 15 passed, 0 failed","3) Failure injection: Neo4j was tried only 3 times in 5 requests (2 were skipped)","4) Latency: get_transaction (MongoDB) median 1.399 ms, p95 6.387 ms","TOTAL: 24 passed, 0 failed"]){await sleep(380);L("l162",t)}LAB.l162.d={}}
});
const M16=[["Q1 courses of Alice","find() on an array: 1 document read","SELECT by partition key: 1 partition read","MATCH, 1 hop"],["Q2 students in C1","find() on the roster: 1 document read","SELECT by partition key: 1 partition read","MATCH, 1 hop"],["Q3 classmates of Alice","find() with $in on a multikey index: 2 steps","no JOIN: 3 partition reads, merged in the application","one MATCH pattern, 2 hops"]];
const A16=[["Alice enrolls in CS301 with no prerequisites","refused","missing CS101, CS201 (graph)"],["Alice completes CS101 and CS201, enrolls again","accepted","enrollment + outbox event in MongoDB"],["Worker drains the outbox","2 events moved","Cassandra partition (student_id, day)"],["Read the partition back","ENROLLED, then ENROLL_REJECTED","CLUSTERING ORDER BY DESC: newest first"]];
const L16=[["get_transaction (MongoDB)","1.399","6.387"],["get_user_profile (Cassandra, simulated)","0.005","0.007"],["detect_fraud_rings, 1 hop (Neo4j, simulated)","0.004","0.004"],["detect_fraud_rings, 3 hops (Neo4j, simulated)","0.006","0.007"],["analyze_transaction (all three)","0.910","1.512"]];
const DAYC=[0,0,0,31,49,12,0];   // simulated events per day, oldest first, today = the rows below
const SEED16=Array.from({length:10},(_,i)=>({t:`${new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"short"})}, 09:${String(59-i*2).padStart(2,"0")}`,u:"demo-admin",a:"auth.login",d:"",o:"ok"}));
const C16={who:"",f:{txn:"T1001",live:null,status:null,probed:false,err:"",down:false,fails:0,tried:0,open:false,out:null,runs:0}};
const TX16={"T1001":{amt:"9,500.00",m:"QuickCash",bad:true},"T2001":{amt:"42.50",m:"Bookshop",bad:false}};
const rows16=()=>[...C13.audit.map(a=>({t:a.t,u:a.u,a:a.a,d:a.d,o:"ok"})),...SEED16];
pages.hybrid=function(){
  const n=rows16().length,f=C16.f;
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 16: Cassandra and Neo4j</p>
  <div class="rs-head"><div><h1>Chapter 16: Cassandra and Neo4j</h1><p class="lead">The same platform in three databases at once: its audit log in Cassandra for the admins, and a fraud review that asks MongoDB, Cassandra and Neo4j the part each answers best.</p><span class="badge passed">Lab results shown are your recorded runs</span></div>
  <div class="card"><b>Three stores</b><div class="members" style="margin-top:8px">${[["REAL SERVER","MongoDB: source of truth"],["SIMULATED","Cassandra: audit log"],["SIMULATED","Neo4j: transfer graph"]].map(([r,t])=>`<div class="mem"><small>${r}</small>${t}</div>`).join("")}</div></div></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Data used</b><code>chapter-16 database</code></div>
  <p>This platform's audit events and simulated billing accounts, kept in three databases</p>
  <div class="row"><div class="card" style="margin:0"><span class="stat">${n}</span> <span class="meta">audit events today</span></div><div class="card" style="margin:0"><span class="stat">${Object.keys(TX16).length}</span> <span class="meta">sample transactions to analyse</span></div></div></div>
  <h2>Live from the platform</h2><div class="labs">
  <div class="card"><b>Audit log in Cassandra</b><p class="meta">Every sign-in, account change, case change and lab run, partitioned by day and by person.</p>
    <div class="row"><div>Events today<div class="stat">${n}</div></div></div><p><a href="#ops/audit">Open the audit log (admins)</a></p></div>
  <div class="card"><b>Fraud review</b><p class="meta">Simulated billing accounts: transactions in MongoDB, timelines in Cassandra, transfers in Neo4j, each behind a circuit breaker.</p>
    <p>Circuit breakers: mongodb closed, cassandra closed, neo4j ${f.open?"open":"closed"}</p><p><a href="#mod/fraud">Open the fraud review (moderators)</a></p></div></div>
  <h2>Labs</h2><div class="labs">
  ${card("l161","Lab 16.1","One model in MongoDB, Cassandra and Neo4j",d=>`<h3>same answers in all three; classmates of a student: 3 partition reads in Cassandra, one pattern in Neo4j</h3>
    <table><tr><th>Question</th><th>MongoDB</th><th>Cassandra</th><th>Neo4j</th></tr>${M16.map(r=>`<tr><td>${r[0]}</td>${r.slice(1).map(x=>`<td>${x}</td>`).join("")}</tr>`).join("")}</table>
    <p class="ok">12 passed, 0 failed · Q1 = C1, C2 · Q2 = Alice, Bob · Q3 = Bob, Carol</p>`,"Each model answers its own questions in one read; the many-to-many question is a pipeline in MongoDB, an application join in Cassandra and one pattern in Neo4j.")}
  ${card("a161","Activity 16.1","A hybrid architecture",d=>`<h3>1 enrollment refused by the prerequisite chain, 1 accepted; 2 audit events read back newest first</h3>
    <table><tr><th>Step</th><th>Result</th><th>Where</th></tr>${A16.map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td><td>${r[2]}</td></tr>`).join("")}</table><p class="ok">10 passed, 0 failed</p>`,"The graph decides, the document store records, the wide-column store audits; an outbox avoids writing to two databases from the API.")}
  <div style="grid-column:1/-1">${card("l162","Lab 16.2","A hybrid query service (fraud detection)",d=>`<h3>24 checks pass (9 unit tests, 15 integration and failure-injection); a dead Neo4j is skipped after 3 failures</h3>
    <table><tr><th>Method</th><th>median (ms)</th><th>p95 (ms)</th></tr>${L16.map(r=>`<tr><td>${r[0]}</td><td class="mono">${r[1]}</td><td class="mono">${r[2]}</td></tr>`).join("")}</table>
    <p class="meta">Only the MongoDB row is a real network round trip; Cassandra and Neo4j ran in memory. With real servers the documented figures are about 3 to 8 ms (Cassandra) and 10 to 500 ms (Neo4j).</p>`,"One service, three backends, each behind a circuit breaker: when one database is down the other two still answer.")}</div></div>
  <p class="meta" style="margin-top:16px">Real runs: <code>Lab 16.1 - Model Data in Three Databases.py</code>, <code>Activity for 16.1 - Try it yourself.py</code> and <code>Lab 16.2 - Build a Hybrid Query Service.py</code> (need the MongoDB server; set <code>CH16_URI</code> before starting server.py if yours is not on 27047).</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};
/* ---- Operations > Audit log ---- */
const opsAudit=function(){
  const all=rows16(),w=C16.who.trim().toLowerCase(),shown=w?all.filter(r=>r.u.toLowerCase().includes(w)):all;
  const by={};all.forEach(r=>by[r.a]=(by[r.a]||0)+1);const top=Object.entries(by).sort((x,y)=>y[1]-x[1])[0];
  const week=DAYC.reduce((s,x)=>s+x,0)+all.length,days=DAYC.map((c,i)=>[i==6?all.length:c,new Date(Date.now()-(6-i)*864e5)]),mx=Math.max(1,...days.map(d=>d[0]))*1.15;
  const day=new Date().toISOString().slice(0,10);
  view.innerHTML=`<p class="meta">Administrators</p><h1>Operations</h1><p class="lead">Running this platform's data: the deployment and its failover, monitoring and backups, and the audit trail.</p>
  <div class="row" id="opstabs" style="margin-bottom:12px"></div>
  <div class="card"><b>Audit log</b><p class="meta">Every sign-in, account change, case change, lab run and review decision on this platform, kept in Cassandra (Chapter 16): one partition per day and one per person, newest first. Simulated here; Back up now, Verify restore, alert acknowledgements and fraud analyses add entries.</p>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">${stat("Events today",all.length)}${stat("Last 7 days",week)}${stat("Most frequent",top?top[0]+" ("+top[1]+")":"none")}${stat("Read from Cassandra","one partition")}</div>
  <svg viewBox="0 0 640 150" width="100%" role="img" aria-label="Events per day" style="margin-top:10px">${days.map((d,i)=>{const w2=640/7,h=d[0]/mx*100;return `<rect x="${i*w2+w2*.25}" y="${120-h}" width="${w2*.5}" height="${h}" rx="3" style="fill:var(--acc)"><title>${d[0]} events</title></rect><text x="${i*w2+w2/2}" y="138" text-anchor="middle" font-size="10" style="fill:var(--mute)">${String(d[1].getMonth()+1).padStart(2,"0")}-${String(d[1].getDate()).padStart(2,"0")}</text>`}).join("")}</svg>
  <div class="row" style="margin:10px 0"><span class="meta">Day</span><span class="tag">${day}</span><input id="au" value="${esc(C16.who)}" placeholder="or one person (username)" aria-label="Username"><button class="alt" id="as">Show</button></div>
  <p class="mono meta">${w?`SELECT * FROM events_by_user WHERE username = '${esc(w)}' LIMIT 200`:`SELECT * FROM events_by_day WHERE day = '${day}' LIMIT 200`}</p>
  ${shown.length?`<table><tr><th>Time</th><th>Who</th><th>Action</th><th>Detail</th><th>Outcome</th></tr>${shown.map(r=>`<tr><td class="mono">${r.t}</td><td>${esc(r.u)}</td><td class="mono">${esc(r.a)}</td><td>${esc(r.d)}</td><td><span class="badge passed">${r.o}</span></td></tr>`).join("")}</table>`:'<p class="meta">No events for that person today.</p>'}</div>`;
  $("#as").onclick=()=>{C16.who=$("#au").value;redraw()};
  $("#au").onkeydown=e=>{if(e.key=="Enter")$("#as").click()};
};
/* ---- Moderation > Fraud review ---- */
function analyzeSim16(){
  const f=C16.f,t=TX16[f.txn],o={id:f.txn,amt:t.amt,m:t.m,mongo:`${t.amt} at ${t.m}`,cass:"10 newest events, newest first"};
  f.runs++;
  if(f.down){ if(f.open){o.neo="skipped: circuit breaker open"}else{f.tried++;f.fails++;o.neo="unavailable";if(f.fails>=3)f.open=true} }
  else{f.fails=0;f.open=false;o.neo=t.bad?["U2 (1 hop)","U3 (2 hops)","U4 (3 hops)"]:["U7 (1 hop)"]}
  o.verdict=Array.isArray(o.neo)?(t.bad?"REVIEW: possible fraud ring, connected to 3 accounts within 3 hops":"OK: no flags, connected to 1 account"):"Partial answer: MongoDB and Cassandra data returned, Neo4j reported unavailable";
  f.out=o;audit("fraud.analyze",`${f.txn}: ${o.verdict.split(":")[0]}`);redraw()}
const liveOut16=d=>{const r=d.result,tx=r.transaction,un=r.unavailable,nb=d.breakers.neo4j;
  return {id:r.txn_id,
    mongo:tx?`${Number(tx.amount).toLocaleString("en-US",{minimumFractionDigits:2})} at ${tx.merchant}`:(un.includes("mongodb")?"unavailable":"transaction not found"),
    cass:un.includes("cassandra")?"unavailable":`${r.recent_events.length} newest events, newest first`,
    neo:un.includes("neo4j")?(nb.open?"unavailable: circuit breaker open":"unavailable"):r.connected_accounts.map(a=>`${a.id} (${a.hops} hop${a.hops>1?"s":""})`),
    verdict:un.length?`Partial answer: ${un.join(", ")} reported unavailable`+(r.flags.length?` · ${r.flags.join("; ")}`:""):(r.verdict=="OK"?"OK: no flags":`REVIEW: ${r.flags.join("; ")}`)}};
async function analyze16(){
  const f=C16.f;
  if(!DEMO){
    try{
      const r=await fetch(`${API}/fraud/analyze/${f.txn}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({neo4j_down:f.down})});
      const d=await r.json();if(!r.ok)throw new Error(d.error||("HTTP "+r.status));
      f.live=d;f.err="";f.out=liveOut16(d);audit("fraud.analyze",`${f.txn}: ${f.out.verdict.split(":")[0]} (live)`);redraw();return}
    catch(e){f.live=null;f.err=String(e.message||e)}
  }
  analyzeSim16()}
function fraudProbe(){const f=C16.f;if(f.probed||DEMO)return;f.probed=true;
  fetch(`${API}/fraud/status`).then(r=>r.json().then(d=>({ok:r.ok,d}))).then(({ok,d})=>{if(ok)f.status=d;else f.err=d.error||"";redraw()}).catch(()=>{f.err="server.py is not running";redraw()})}
const modFraud=function(){
  fraudProbe();const f=C16.f,o=f.out,canRun=ROLE!="Client",L0=f.live||f.status,B=L0&&L0.breakers,M=L0&&L0.mode,brk=(n,open)=>`<span class="tag ${open?"":"t-embed"}">${n} ${open?"open":"closed"}</span>`;
  view.innerHTML=`<p class="meta">Moderators and admins</p><h1>Moderation</h1><p class="lead">The reviews that keep this platform's data trustworthy: indicators that may be false positives, suspicious billing accounts, monitoring alerts and the organisations' activity.</p>
  <div class="row" id="modtabs" style="margin-bottom:12px"></div>
  <div class="card"><b>Fraud review</b><p class="meta">Billing accounts that pass credits around a cycle or share a device (simulated accounts, Chapter 16). Each analysis asks MongoDB for the transaction, Cassandra for the account's timeline and Neo4j for the transfer graph; a database that is down is skipped by its circuit breaker.</p>
  <p><span class="badge ${M?"passed":""}">${M?`Live service: MongoDB ${M.mongodb} · Cassandra ${M.cassandra} · Neo4j ${M.neo4j}`:"Simulated in the browser"}</span> ${M?"":`<span class="meta">${f.err?"Live service not available: "+esc(f.err):"Start server.py for the live service."}</span>`}</p>
  <div class="row"><select id="ft" aria-label="Transaction">${Object.entries(TX16).map(([k,v])=>`<option value="${k}" ${k==f.txn?"selected":""}>${k} · ${v.amt} at ${v.m}</option>`).join("")}</select>
  <label class="row" style="gap:6px;flex:none"><input type="checkbox" id="fd" style="flex:none;width:auto;margin:0" ${f.down?"checked":""}> Simulate Neo4j down</label>
  <button id="fa" ${canRun?"":'disabled title="Clients cannot review"'}>Analyze</button><button class="alt" id="fr">Reset breakers</button></div>
  <div class="row" style="margin-top:8px">${brk("mongodb",B?B.mongodb.open:false)}${brk("cassandra",B?B.cassandra.open:false)}${brk("neo4j",B?B.neo4j.open:f.open)}<span class="meta">${B?`Neo4j failed ${B.neo4j.failures} time(s) in a row`:`Neo4j tried ${f.tried} time(s)`}; 3 consecutive failures open the breaker</span></div></div>
  ${o?`<div class="card"><b>Analysis of ${o.id}</b><table><tr><th>Backend</th><th>Answer</th></tr><tr><td>MongoDB (transaction)</td><td>${esc(o.mongo)}</td></tr><tr><td>Cassandra (timeline)</td><td>${o.cass}</td></tr><tr><td>Neo4j (transfer graph)</td><td>${Array.isArray(o.neo)?(o.neo.length?"connected accounts: "+o.neo.join(", "):"no connected accounts"):o.neo}</td></tr></table><p class="${o.verdict.startsWith("REVIEW")||o.verdict.startsWith("Partial")?"bad":"ok"}">${esc(o.verdict)}</p></div>`:'<p class="meta">Pick a transaction and press Analyze.</p>'}`;
  $("#ft").onchange=e=>{f.txn=e.target.value};$("#fd").onchange=e=>{f.down=e.target.checked};
  $("#fa").onclick=analyze16;$("#fr").onclick=async()=>{if(!DEMO){try{const r=await fetch(`${API}/fraud/reset`,{method:"POST"});if(r.ok)f.status=await r.json()}catch(e){}}Object.assign(f,{fails:0,tried:0,open:false,out:null,live:null});redraw()};
};
pages.mod=function(a){if(a)MODTAB=a;MODTAB=="fp"?modFP():MODTAB=="fraud"?modFraud():MODTAB=="orgs"?modOrgs():modAlerts();modTabs()};

/* ===== Chapter 17: vector search and RAG (#rag, #ask, Operations > Ask index) =====
   Results are the recorded runs of your scripts (--offline). Run executes them through server.py.
   Edit RAGCFG below to match the size of your real index. ===== */
["l171","a171","l172"].forEach(k=>LAB[k]={st:"idle",log:[],d:null,open:false});
const RAGCFG={chunks:2648,reports:49,dims:768,embed:"nomic-embed-text",llm:"llama3.2"};
const Q17=[["What entry points does ransomware use?","ransomware","0.6106"],["What are the signs of a phishing email?","phishing","0.6311"],["What is MITRE ATT&CK used for?","mitre_attack","0.6524"]];
const CV17=[["What defences work against it?","ransomware","2"],["Which attacker tactics does ATT&CK list?","mitre_attack","4"],["What can staff do about phishing emails?","phishing","6"]];
const CMP17=[["HNSW","M=16, efConstruction=64 (search width 100)",4.16,1.104,97.4],["IVF","nlist=100, nprobe=10",0.06,0.118,83.2]];
const HM17=[[8,4.20,1.217,88.0],[16,4.61,1.153,97.4],[32,6.74,2.154,99.8]];
const IN17=[[50,.04,.292,84.4],[100,.06,.121,83.2],[200,.10,.066,85.5]];
const CH17=[[1.167,96.9],[1.098,97.4],[1.231,98.2],[1.137,98.8]],CI17=[[.162,83.2],[.860,97.1],[1.503,100]];
Object.assign(runs,{
async l171(){for(const t of["Mode: OFFLINE (in-memory store, hashed embeddings, template LLM)","1) Chunking: 100-word window, 20-word overlap: 4 documents -> 8 chunks","2) Embed and store: 8 chunk documents with text, source and embedding","3) Retrieval: top 3 chunks per question; the right document came first 3 of 3 times","4) Prompt built from the 3 chunks and the question; first turn has no earlier messages","RESULT: 11 passed, 0 failed"]){await sleep(380);L("l171",t)}
  LAB.l171.d={docs:4,chunks:8,q:Q17}},
async a171(){for(const t of["Mode: OFFLINE (in-memory store, hashed embeddings, template LLM)","5) Conversation memory: 3 follow-up questions asked","   every query and answer stored in 'conversations': 8 messages for 4 exchanges","   the 3rd follow-up prompt carries 6 earlier messages","6) Memory window: history returns 10 messages (5 exchanges), the first question dropped out","RESULT: 17 passed, 0 failed"]){await sleep(380);L("a171",t)}
  LAB.a171.d={cv:CV17,stored:8}},
async l172(){for(const t of["Mode: OFFLINE (numpy HNSW and IVF, synthetic embeddings)","1) 5,000 documents of 384 dimensions, exact top-20 for 100 queries","3) HNSW 97.4 % recall, IVF 83.2 % recall","4) HNSW and IVF parameter experiments","7) Latency-recall curve saved to latency_recall_curve.png","RESULT: 8 passed, 0 failed"]){await sleep(380);L("l172",t)}
  LAB.l172.d={}}
});
const lr17=()=>{const W=420,H=230,L0=44,lo=Math.log10(.05),hi=Math.log10(2),X=v=>L0+(Math.log10(v)-lo)/(hi-lo)*(W-L0-12),Y=v=>H-34-(v-80)/20*(H-56);
  const pl=(a,c,dash)=>{const s=a.slice().sort((x,y)=>x[0]-y[0]);return `<polyline fill="none" stroke="${c}" stroke-width="2" ${dash?'stroke-dasharray="5 4"':""} points="${s.map(p=>X(p[0])+","+Y(p[1])).join(" ")}"/>`+s.map(p=>`<circle cx="${X(p[0])}" cy="${Y(p[1])}" r="4" fill="${c}"><title>${p[0]} ms, ${p[1]} % recall</title></circle>`).join("")};
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Latency against recall for HNSW and IVF">
  ${[80,90,100].map(v=>`<line x1="${L0}" x2="${W-8}" y1="${Y(v)}" y2="${Y(v)}" style="stroke:var(--line)"/><text x="${L0-5}" y="${Y(v)+4}" text-anchor="end" font-size="10" style="fill:var(--mute)">${v}%</text>`).join("")}
  ${[.1,.5,1,2].map(v=>`<text x="${X(v)}" y="${H-16}" text-anchor="middle" font-size="10" style="fill:var(--mute)">${v}</text>`).join("")}
  <text x="${(L0+W)/2}" y="${H-2}" text-anchor="middle" font-size="10" style="fill:var(--mute)">average query latency (ms, log scale)</text>
  ${pl(CH17,"#2f6fd0")}${pl(CI17,"#c2570a",1)}</svg>
  <div class="row" style="gap:12px"><span class="meta"><span class="dot" style="background:#2f6fd0"></span>HNSW (efConstruction 32 to 256)</span><span class="meta"><span class="dot" style="background:#c2570a"></span>IVF (nprobe 10, 50, 100)</span></div>`};
/* ---- Ask: conversation with memory (simulated by keyword overlap over the seeded articles) ---- */
const CONV17=[],J17={st:"idle"},R17={st:null,err:"",probed:false};
function ask17(q){
  const prev=[...CONV17].reverse().find(m=>m.role=="user"),w=(((prev?prev.content+" ":"")+q+" "+q).toLowerCase().match(/[a-z0-9-]{3,}/g)||[]),
  sc=a=>w.reduce((s,x)=>s+(a.title.toLowerCase().includes(x)?2:0)+(a.tags.some(t=>t.includes(x))?1:0),0),
  hits=DB.articles.map(a=>({a,s:sc(a)})).filter(x=>x.s>0).sort((x,y)=>y.s-x.s||y.a.published-x.a.published).slice(0,4).map(x=>({t:x.a.title,tags:x.a.tags,sim:Math.min(.95,.5+x.s*.05)})),
  earlier=Math.min(CONV17.length,10),
  ans=hits.length?`Passages found in ${hits.length} reports: ${hits.map((h,i)=>h.t+" ["+(i+1)+"]").join("; ")}.`:"No relevant reports were retrieved, so a grounded answer is not possible.";
  CONV17.push({role:"user",content:q},{role:"assistant",content:ans,hits,earlier});
  audit("rag.ask",q.slice(0,60));redraw()}
pages.ask=function(){
  const msgs=CONV17.map(m=>m.role=="user"?`<div class="row" style="justify-content:flex-end"><div class="card" style="margin:6px 0;max-width:80%">${esc(m.content)}</div></div>`
    :`<div class="card" style="margin:6px 0;max-width:92%"><p>${esc(m.content)}</p>${m.hits.map((h,i)=>`<div class="card" style="margin:4px 0"><b>[${i+1}] ${esc(h.t)}</b> <span class="meta">similarity ${h.sim.toFixed(3)}</span><div>${h.tags.map(t=>`<span class="tag t-embed">${t}</span>`).join("")}</div></div>`).join("")}<div class="meta">Simulated by keyword overlap (the real answer is written by ${RAGCFG.llm} from the retrieved passages) · ${m.earlier} earlier messages used</div></div>`).join("");
  view.innerHTML=`<p class="meta">Chapter 17 · lab17</p><div class="row" style="justify-content:space-between"><h1>Ask CTI Verify</h1><button class="alt" id="fg" ${CONV17.length?"":"disabled"}>Forget this conversation</button></div>
  <p class="lead">Questions answered from the annual security reports this platform verifies threats against, each claim numbered to the report it comes from.</p>
  <div class="card ref"><b>How it answers:</b> <span class="meta">your question is turned into a vector and the closest report passages are found with $vectorSearch; a language model writes the answer from those passages only, citing them as [1], [2]. Your last five exchanges are remembered, so you can ask follow-ups.</span></div>
  ${msgs||'<p class="meta">Ask a question to start. Try "Which ransomware groups are most active?" then a follow-up such as "How do they get in?".</p>'}
  <form class="row" id="aq" style="margin-top:12px"><input id="aqi" placeholder="Ask about a threat, a technique or a trend in the reports" aria-label="Question" ${ROLE=="Client"&&false?"disabled":""}><button>Ask</button></form>`;
  $("#aq").onsubmit=e=>{e.preventDefault();const q=$("#aqi").value.trim();if(q)ask17(q)};
  $("#fg").onclick=()=>{CONV17.length=0;audit("rag.forget","conversation cleared");redraw()};
};
/* ---- Operations > Ask index ---- */
const opsAsk=function(){
  const asked=CONV17.filter(m=>m.role=="user").length,can=ROLE=="Administrator";
  view.innerHTML=`<p class="meta">Administrators</p><h1>Operations</h1><p class="lead">Running this platform's data: the deployment and its failover, monitoring and backups, organisations, the audit trail and the Ask index.</p>
  <div class="row" id="opstabs" style="margin-bottom:12px"></div>
  <div class="card"><b>Ask index</b><p class="meta">The chunks of the annual reports, embedded (${RAGCFG.dims} dimensions) into the vector index Ask CTI Verify searches (Chapter 17). The text never leaves this computer.</p>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(170px,1fr))">${stat("Chunks indexed",RAGCFG.chunks.toLocaleString()+" from "+RAGCFG.reports+" reports")}${stat("Answers by",RAGCFG.llm)}${stat("Questions asked",asked)}${stat("Vector size",RAGCFG.dims+" · "+RAGCFG.embed)}</div>
  <p class="meta">Job: ${J17.st}</p>
  <button id="ix" ${can&&J17.st=="idle"?"":"disabled"} ${can?"":'title="Administrators only"'}>${J17.st=="running"?"Indexing …":"Index the reports"}</button></div>`;
  $("#ix")&&($("#ix").onclick=async()=>{J17.st="running";redraw();await sleep(1500);J17.st="idle";audit("rag.index",`${RAGCFG.chunks} chunks from ${RAGCFG.reports} reports`);redraw()});
};
/* ---- Chapter 17 page ---- */
pages.rag=function(){
  if(!R17.probed&&!DEMO){R17.probed=true;fetch(`${API}/rag/status`).then(r=>r.json()).then(d=>{R17.st=d;redraw()}).catch(()=>{R17.err="server.py is not running";redraw()})}
  const s=R17.st,ok=x=>x?"t-embed":"t-ref",asked=CONV17.filter(m=>m.role=="user").length;
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 17: vector search and RAG</p>
  <div class="rs-head"><div><p class="meta mono">lab17</p><h1>Chapter 17: vector search and RAG</h1><p class="lead">Chapter 7's annual reports become answers: chunks embedded into a vector index, retrieved with $vectorSearch and answered with citations; HNSW and IVF measured against exact search.</p><span class="badge passed">Lab results shown are your recorded runs (--offline)</span></div>
  <div class="card"><b>Pipeline</b><div class="members" style="margin-top:8px">${[["EMBED",RAGCFG.embed],["STORE","vector index"],["ANSWER",RAGCFG.llm]].map(([r,n])=>`<div class="mem"><small>${r}</small>${n}</div>`).join("")}</div>
  <p class="meta" style="margin-top:8px">Needed only for online mode (set <code>CH17_ONLINE=1</code> before starting server.py):</p>
  <div class="row">${s?`<span class="tag ${ok(s.ollama)}">Ollama ${s.ollama?"running":"not reachable"}</span><span class="tag ${ok(s.embed_model)}">${RAGCFG.embed} ${s.embed_model?"pulled":"missing"}</span><span class="tag ${ok(s.chat_model)}">${RAGCFG.llm} ${s.chat_model?"pulled":"missing"}</span><span class="tag ${ok(s.atlas_configured)}">MONGO_URI ${s.atlas_configured?"set":"missing"}</span>`:`<span class="meta">${esc(R17.err||"Unknown until server.py answers.")}</span>`}</div></div></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Chapter 7 data used</b><code>chapter-17 database</code></div><p>The annual reports' chunks for Ask, and the event titles used to compare the indexes</p>
  <div class="row"><div class="card" style="margin:0"><span class="stat">${RAGCFG.chunks.toLocaleString()}</span> <code>chunks</code> <span class="meta">filled by Lab 17.1</span></div><div class="card" style="margin:0"><span class="stat">${CONV17.length}</span> <code>conversations</code> <span class="meta">filled by Activity 17.1</span></div><div class="card" style="margin:0"><span class="stat">5,000</span> <code>docs</code> <span class="meta">Lab 17.2</span></div></div></div>
  <h2>Live from the lab</h2><div class="labs">
  <div class="card"><b>Ask CTI Verify</b><p class="meta">The reports' chunks in a vector index; answers cite the passages they come from.</p>
    <div class="grid" style="grid-template-columns:1fr 1fr">${stat("Reports indexed",RAGCFG.chunks.toLocaleString()+" chunks from "+RAGCFG.reports+" reports")}${stat("Answers by",RAGCFG.llm)}${stat("Questions asked",asked)}${stat("Vector size",RAGCFG.dims)}</div>
    <p style="margin-top:10px"><a href="#ask">Ask a question</a> · <a href="#ops/ask">Ask index (admins)</a></p></div>
  <div class="card"><b>HNSW against IVF (Lab 17.2)</b><p class="meta">Recall@20 against exact search over 100 queries, 5,000 documents: HNSW swept over efConstruction, IVF over nprobe.</p>${lr17()}</div></div>
  <h2>Labs</h2><div class="labs">
  ${card("l171","Lab 17.1","A simple RAG pipeline",d=>`<h3>${d.chunks} chunks from ${d.docs} documents; the right document came first for 3 of 3 questions</h3>
    <table><tr><th>Question</th><th>Top document</th><th>Score</th></tr>${d.q.map(r=>`<tr><td>${esc(r[0])}</td><td class="mono">${r[1]}</td><td class="mono">${r[2]}</td></tr>`).join("")}</table>
    <p class="ok">11 passed, 0 failed · chunks of 100 words with 20 words overlap, top 3 per query</p>`,"Retrieval-augmented generation: the answer is built from the passages $vectorSearch returns.")}
  ${card("a171","Activity 17.1","Conversation memory",d=>`<h3>${d.stored} messages stored for 4 exchanges; only the last 5 exchanges are sent</h3>
    <table><tr><th>Follow-up</th><th>Answered from</th><th>Earlier messages</th></tr>${d.cv.map(r=>`<tr><td>${esc(r[0])}</td><td class="mono">${r[1]}</td><td>${r[2]}</td></tr>`).join("")}</table>
    <p class="ok">17 passed, 0 failed · the first question dropped out of the 10-message window</p>`,"The last exchanges, stored in MongoDB, make follow-up questions understood.")}
  <div style="grid-column:1/-1">${card("l172","Lab 17.2","HNSW against IVF",d=>`<h3>HNSW 97.4 % recall in 1.104 ms; IVF at nprobe 10 83.2 % in 0.118 ms</h3>
    <div class="split"><div><table><tr><th>Index</th><th>Parameters</th><th>Build (s)</th><th>Latency (ms)</th><th>Recall (%)</th></tr>${CMP17.map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td><td class="mono">${r[2].toFixed(2)}</td><td class="mono">${r[3].toFixed(3)}</td><td class="mono">${r[4].toFixed(1)}</td></tr>`).join("")}</table>
    <table style="margin-top:8px"><tr><th>HNSW M</th><th>Build (s)</th><th>Latency (ms)</th><th>Recall (%)</th></tr>${HM17.map(r=>`<tr><td>${r[0]}</td><td class="mono">${r[1].toFixed(2)}</td><td class="mono">${r[2].toFixed(3)}</td><td class="mono">${r[3].toFixed(1)}</td></tr>`).join("")}</table>
    <table style="margin-top:8px"><tr><th>IVF nlist</th><th>Build (s)</th><th>Latency (ms)</th><th>Recall (%)</th></tr>${IN17.map(r=>`<tr><td>${r[0]}</td><td class="mono">${r[1].toFixed(2)}</td><td class="mono">${r[2].toFixed(3)}</td><td class="mono">${r[3].toFixed(1)}</td></tr>`).join("")}</table></div>
    <div>${lr17()}<p class="meta">IVF probing all 100 lists is exact (100 % recall) but as slow as 1.5 ms. Offline latencies are numpy numbers, not Atlas numbers.</p></div></div>
    <p class="ok">8 passed, 0 failed</p>`,"HNSW keeps recall high and stable; IVF is cheap to build and trades recall for the lists it probes.")}</div></div>
  <p class="meta" style="margin-top:16px">Real runs (offline, no Atlas needed): <code>Lab 17.1 - Build a Simple RAG Pipeline.py --offline</code>, <code>Activity for 17.1 - Try it yourself.py --offline</code>, <code>Lab 17.2 - Compare HNSW and IVF Vector Indexes.py --offline</code> (Lab 17.2 needs <code>pip install numpy matplotlib</code> and takes a minute or two).</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};

/* ===== Chapter 18: comparative capstone (#capstone, Operations > Sources, Moderation > False positives) =====
   Lab and Activity results are the recorded --offline runs of your scripts. The false-positive candidates, source
   reliability and judge scores are SIMULATED from your screenshots of the live site; Run executes the real scripts. ===== */
["l181","a181","l182"].forEach(k=>LAB[k]={st:"idle",log:[],d:null,open:false});
const BM18=[["1. Threat history",0.000,0.001,0.000,"Neo4j"],["2. Target and spread",0.895,19.249,0.058,"Neo4j"],["3. Daily volume analytics",11.904,0.018,12.292,"Cassandra"],["4. Insert batch (ms)",5.904,6.709,4.983,"Neo4j"]];
const TP18=[169372,149054,200700],LD18=[.05,.04,.10];
const REC18=[["Threat history for a source","Cassandra (or MongoDB)","One pre-sorted partition read; MongoDB's embedded last-50 array is nearly as fast"],["Target and spread","Neo4j","One traversal answers who else hit these targets"],["Daily volume analytics","Cassandra (or MongoDB)","(type, day) partitions make counts cheap"],["Real-time insert throughput","Cassandra","Log-structured writes; Neo4j is the costliest per threat"],["False-positive community detection","Neo4j","Graph algorithms on SUSPICIOUS links; details from MongoDB"]];
const SC18=[["1M","~0.3 GB","1 node (3-node set for HA)","3 nodes","1 node (3-node cluster for HA)"],["10M","~3 GB","3-node replica set","3 to 4 nodes","1 primary + 2 secondaries"],["100M","~30 GB","sharded: 3 shards x 3-node sets","6 to 9 nodes, ~2 TB","1 large primary, 128 to 256 GB RAM"]];
Object.assign(runs,{
async l181(){for(const t of["loaded MongoDB: 100,000 threats in 0.0s","loaded Cassandra: 100,000 threats in 0.0s","loaded Neo4j: 100,000 threats in 0.1s","Query (median of 10 runs, ms): history, target and spread, daily volume, insert batch","Report written: Lab 18.1 - Comparative Report.txt"]){await sleep(380);L("l181",t)}
  LAB.l181.d={}},
async a181(){for(const t of["Threats: 100,000 | SUSPICIOUS edges: 617","Communities (size>=3): 17","FLAGGED community: 20 sources | weight/source=26.5 | z=4.0","  Mongo cross-ref: 18,362 threats | top types=scan 15,620, ddos 721, botnet 716","  overlap with planted ring: 75% -> review as likely false-positive cluster"]){await sleep(380);L("a181",t)}
  LAB.a181.d={}},
async l182(){for(const t of["Reading the latency table from Lab 18.1 - Comparative Report.txt","Writing the 8 sections: summary, methodology, architecture, schema, performance, ergonomics, scalability, recommendation","Report written: Lab 18.2 - Comparative Analysis Report.txt"]){await sleep(380);L("l182",t)}
  LAB.l182.d={}}
});
/* ---- simulated false-positive review (from the live site's screenshots) ---- */
const FPC18=[["domain","discord.com","shared or benign infrastructure (discord.com); one source only, not graded A; attributed to 9 families",6],["domain","raw.githubusercontent.com","shared or benign infrastructure (githubusercontent.com); attributed to 4 families",6],["domain","api.telegram.org","shared or benign infrastructure (telegram.org); attributed to 15 families",5],["ip","0.0.0.0","public resolver or reserved address 0.0.0.0; attributed to 12 families",5],["domain","github.com","shared or benign infrastructure (github.com); attributed to 5 families",5],["ip","127.0.0.1","public resolver or reserved address 127.0.0.1; one source only",4],["domain","t.me","shared or benign infrastructure (t.me); one source only",4],["hash","10f705728d228ad949b7894c1a85a2b1","attributed to 4 different families; community of 4 families tied by shared indicators (z 2.12)",4],["hash","2e3e1bcd44cc3cbec4f5ca9991d14a326d3cc6bf78fe6e0d434c9b5f7e1ae6ab","attributed to 8 families; community of 16 families tied by shared indicators (z 5.77)",4],["domain","pastebin.com","shared or benign infrastructure (pastebin.com); one source only",4]];
const D18={},F18={all:true,undec:true};
const pct18=(rows,color)=>rows.map(([n,v,sub])=>`<div class="bars" style="grid-template-columns:130px 1fr 56px"><span>${esc(n)}${sub?` <span class="meta">${sub}</span>`:""}</span><div class="bar"><i style="width:${Math.min(100,v)}%;background:${color}"></i></div><span class="mono">${v} %</span></div>`).join("");
const FEEDS18=[["nocacti",43.7],["otx",43],["rosti",10.5],["precisionsec",3],["threatfox",.7],["malwarebazaar",0],["urlhaus",0],["infoblox",0],["siberkapan",0]];
const JUDGE18=[["MongoDB",97,61],["Cassandra",83,14],["Neo4j",100,18],["2 of 3",89,18],["any of 3",96,62]];
const PAIRS18=[["otx","rosti",849],["malwarebazaar","threatfox",771],["threatfox","urlhaus",318],["nocacti","siberkapan",261],["precisionsec","threatfox",230],["malwarebazaar","urlhaus",220]];
/* ---- Chapter 18 page ---- */
pages.capstone=function(){
  const win=BM18.map(r=>r[4]);
  view.innerHTML=`<p class="meta"><a href="#tour">Course tour</a> / Chapter 18: comparative capstone</p>
  <div class="rs-head"><div><p class="meta mono">lab18</p><h1>Chapter 18: comparative capstone</h1><p class="lead">Chapter 7's threats in MongoDB, Cassandra and Neo4j: which database answers which question best, and which indicators are probably false positives for moderators to review.</p><span class="badge passed">Lab results shown are your recorded runs (--offline)</span></div>
  <div class="card"><b>Three databases</b><div class="members" style="margin-top:8px">${[["DOCUMENT","MongoDB"],["WIDE-COLUMN","Cassandra"],["GRAPH","Neo4j"]].map(([r,n])=>`<div class="mem"><small>${r}</small>${n}</div>`).join("")}</div></div></div>
  <div class="card"><div class="row" style="justify-content:space-between"><b>Chapter 7 data used</b><code>chapter-18 database</code></div><p>The same 100,000 threats, each modelled for its own questions</p>
  <div class="row"><div class="card" style="margin:0"><span class="stat">100,000</span> <code>full_threats</code> <span class="meta">MongoDB, Lab 18.1</span></div><div class="card" style="margin:0"><span class="stat">100,000</span> <code>threats_by_source</code> <span class="meta">Cassandra, Lab 18.1</span></div><div class="card" style="margin:0"><span class="stat">617</span> <code>[:SUSPICIOUS]</code> <span class="meta">Neo4j, Activity 18.1</span></div></div></div>
  <h2>Live from the lab</h2><div class="labs">
  <div class="card"><b>Benchmarks (median of 10 runs)</b><p class="meta">The same four questions to each database; the fastest is marked. Offline numbers come from in-memory models: use the shape, not the milliseconds.</p>
    <table><tr><th>Query</th><th>MongoDB</th><th>Cassandra</th><th>Neo4j</th><th>Fastest</th></tr>${BM18.map(r=>`<tr><td>${r[0]}</td>${[1,2,3].map(i=>`<td class="mono ${r[i]==Math.min(r[1],r[2],r[3])?"ok":""}">${r[i].toFixed(3)}</td>`).join("")}<td>${r[4]}</td></tr>`).join("")}
    <tr><td>Insert throughput (threats/s)</td>${TP18.map(v=>`<td class="mono ${v==Math.max(...TP18)?"ok":""}">${v.toLocaleString()}</td>`).join("")}<td>Neo4j</td></tr>
    <tr><td>Bulk load time (s)</td>${LD18.map(v=>`<td class="mono">${v.toFixed(2)}</td>`).join("")}<td>Cassandra</td></tr></table></div>
  <div class="card"><b>False-positive candidates</b><p class="meta">Indicators from this platform's feeds that should probably not be blocked, for moderators to confirm.</p>
    <div class="grid" style="grid-template-columns:1fr 1fr">${stat("Candidates to review",(FPC18.length-Object.keys(D18).length)+" shown here")}${stat("Flagged community (Activity 18.1)","20 sources, z = 4.0")}</div>
    <p style="margin-top:10px"><a href="#mod/fp">Review them (moderators)</a> · <a href="#ops/sources">Source reliability (admins)</a></p></div></div>
  <h2>Labs</h2><div class="labs">
  ${card("l181","Lab 18.1","The comparative system",d=>`<h3>history: all three under 0.01 ms; target and spread: Neo4j ${BM18[1][3]} ms, MongoDB ${BM18[1][1]} ms, Cassandra ${BM18[1][2]} ms</h3>
    <table><tr><th>Query</th><th>Fastest</th></tr>${BM18.map(r=>`<tr><td>${r[0]}</td><td>${r[4]}</td></tr>`).join("")}</table>
    <p class="meta">100,000 threats, 500 sources, 30 days. Writes <code>Lab 18.1 - Comparative Report.txt</code>.</p>`,"Each database wins the query its model was built for: Neo4j the traversal, Cassandra the daily counts.")}
  ${card("a181","Activity 18.1","Communities of connected sources",d=>`<h3>17 communities; 1 flagged: 20 sources, z = 4.0, 75 % overlap with the planted ring</h3>
    <table><tr><th>Step</th><th>Result</th></tr><tr><td>SUSPICIOUS edges (shared target and type)</td><td class="mono">617</td></tr><tr><td>Communities of 3 or more sources</td><td class="mono">17</td></tr><tr><td>MongoDB cross-reference of the flagged community</td><td class="mono">18,362 threats</td></tr><tr><td>Top types</td><td>scan 15,620 · ddos 721 · botnet 716</td></tr><tr><td>Top targets</td><td class="mono">10.0.0.0, 10.0.0.1, 10.0.0.4</td></tr></table>`,"Unusually dense communities share targets and types: often one infrastructure, so they go to the false-positive review.")}
  <div style="grid-column:1/-1">${card("l182","Lab 18.2","The comparative report",d=>`<h3>An 8-section report: MongoDB + Neo4j for detection, Cassandra added for ingest at scale</h3>
    <div class="split"><div><table><tr><th>Access pattern</th><th>Best choice</th><th>Why</th></tr>${REC18.map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td><td class="meta">${r[2]}</td></tr>`).join("")}</table></div>
    <div><table><tr><th>Scale</th><th>Raw</th><th>MongoDB</th><th>Cassandra (RF=3)</th><th>Neo4j</th></tr>${SC18.map(r=>`<tr>${r.map(x=>`<td>${x}</td>`).join("")}</tr>`).join("")}</table><p class="meta">Scalability figures are planning estimates, not measurements.</p></div></div>`,"The recommendation follows measured latency and the schema sizes, not the databases' reputations.")}</div></div>
  <p class="meta" style="margin-top:16px">Real runs (offline, no databases needed): <code>Lab 18.1 - Build the Comparative System.py --offline</code>, <code>Activity for 18.1 - Try it yourself.py --offline</code> (needs <code>pip install networkx numpy</code>) and <code>Lab 18.2 - Write a Comparative Analysis Report.py</code> (run Lab 18.1 first).</p>`;
  view.querySelectorAll("[data-run]").forEach(b=>b.onclick=()=>run(b.dataset.run));
  view.querySelectorAll("[data-log]").forEach(b=>b.onclick=()=>{LAB[b.dataset.log].open=!LAB[b.dataset.log].open;redraw()});
};
/* ---- Moderation > False positives ---- */
const modFP=function(){
  const can=ROLE!="Client",rows=FPC18.filter(c=>!F18.undec||!D18[c[1]]);
  view.innerHTML=`<p class="meta">Moderators and admins</p><h1>Moderation</h1><p class="lead">The reviews that keep this platform's data trustworthy: indicators that may be false positives, suspicious billing accounts, monitoring alerts and the organisations' activity.</p>
  <div class="row" id="modtabs" style="margin-bottom:12px"></div>
  <div class="card"><b>False-positive review</b><p class="meta">Indicators from this platform's feeds that probably should not be blocked: shared or benign infrastructure, a single unrated source, or one indicator blamed on many families. Found by Chapter 18 across MongoDB, Cassandra and Neo4j. Simulated here.</p>
  <div class="card ref" style="margin:8px 0"><b>False positive:</b> <span class="meta">an indicator listed as malicious that is in fact harmless or shared by everyone (a CDN, a public resolver). Blocking it breaks legitimate traffic.</span></div>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(150px,1fr))">${stat("Candidates still to review",FPC18.length-Object.keys(D18).length)}${stat("Decided",Object.keys(D18).length)}</div>
  <label class="row" style="margin:10px 0;gap:6px"><input type="checkbox" id="fu" style="width:auto;flex:none" ${F18.undec?"checked":""}> not decided yet</label>
  ${rows.map(c=>`<div class="card" style="margin:8px 0;${D18[c[1]]?"opacity:.6":""}"><div class="row" style="justify-content:space-between"><span><span class="badge">${c[0]}</span> <b class="mono">${esc(c[1])}</b></span><span class="row"><span class="badge">score ${c[3]}</span>${D18[c[1]]?`<span class="badge passed">${D18[c[1]]=="fp"?"Confirmed false positive":"Kept as threat"}</span>`:`<button class="alt" data-fp="${esc(c[1])}" ${can?"":'disabled title="Clients cannot review"'}>Confirm false positive</button><button class="alt" data-kp="${esc(c[1])}" ${can?"":"disabled"}>Keep as threat</button>`}</span></div><div class="meta">${esc(c[2])}</div></div>`).join("")||'<p class="meta">Nothing left to review.</p>'}</div>`;
  $("#fu").onchange=e=>{F18.undec=e.target.checked;redraw()};
  view.querySelectorAll("[data-fp]").forEach(b=>b.onclick=()=>{D18[b.dataset.fp]="fp";audit("fp.confirm",b.dataset.fp);redraw()});
  view.querySelectorAll("[data-kp]").forEach(b=>b.onclick=()=>{D18[b.dataset.kp]="keep";audit("fp.keep",b.dataset.kp);redraw()});
};
/* ---- Operations > Sources (source reliability) ---- */
const opsSources=function(){
  const top=FEEDS18[0];
  view.innerHTML=`<p class="meta">Administrators</p><h1>Operations</h1><p class="lead">Running this platform's data: the deployment and its failover, monitoring and backups, organisations, the audit trail, the Ask index and the reliability of each feed.</p>
  <div class="row" id="opstabs" style="margin-bottom:12px"></div>
  <div class="card"><b>Source reliability</b><p class="meta">How often each feed's indicators end up as false-positive candidates (Chapter 18), and which feeds report the same indicators (Neo4j SUSPICIOUS links): a feed that copies another adds no corroboration. Simulated here.</p>
  <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(170px,1fr))">${stat("Feeds",FEEDS18.length)}${stat("Highest false-positive rate",top[1]+" % · "+top[0])}${stat("Feeds that copy each other","20 SUSPICIOUS pairs")}${stat("Best database judge","MongoDB")}</div>
  <div class="split" style="margin-top:12px"><div><h2>Is each database right? Precision</h2><p class="meta">Of what each database calls a false positive, the share that really is.</p>${pct18(JUDGE18.map(r=>[r[0],r[1]]),"var(--acc)")}</div>
  <div><h2>Recall</h2><p class="meta">Of the known-benign values, the share each database caught.</p>${pct18(JUDGE18.map(r=>[r[0],r[2]]),"var(--acc)")}</div></div>
  <div class="split" style="margin-top:12px"><div><h2>False-positive rate per feed</h2>${pct18(FEEDS18,"#c0392b")}<p class="meta">The share of a feed's distinct indicators that are false-positive candidates.</p></div>
  <div><h2>Feeds reporting the same indicators</h2><table><tr><th>Feed</th><th>Feed</th><th>Shared</th></tr>${PAIRS18.map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td><td class="mono">${r[2]}</td></tr>`).join("")}</table></div></div>
  <details style="margin-top:12px"><summary><b>Comparative report</b> <span class="meta">(Lab 18.2 recommendation)</span></summary><table style="margin-top:8px"><tr><th>Access pattern</th><th>Best choice</th><th>Why</th></tr>${REC18.map(r=>`<tr><td>${r[0]}</td><td>${r[1]}</td><td class="meta">${r[2]}</td></tr>`).join("")}</table></details></div>`};

function route(){clearInterval(window._t);const [p,arg]=(location.hash.slice(1)||"articles").split("/");
  (pages[p]||pages.articles)(arg&&decodeURIComponent(arg));
  document.querySelectorAll("nav a").forEach(a=>a.classList.toggle("on",a.getAttribute("href")=="#"+(p=="article"?"articles":p)));window.scrollTo(0,0)}
addEventListener("hashchange",route);route();
$("#demo").onchange=e=>{DEMO=e.target.checked};
$("#role").onchange=e=>{ROLE=e.target.value;route()};
/* ---- Final assessment: LLM chat assistant (floating widget; talks to server.py /api/chat) ---- */
(function chatWidget(){
  const sid="web-"+(localStorage.getItem("chat_sid")||(localStorage.setItem("chat_sid",Math.random().toString(36).slice(2,10)),localStorage.getItem("chat_sid")));
  const st=document.createElement("style");
  st.textContent=`#cb-btn{position:fixed;right:20px;bottom:20px;width:52px;height:52px;border-radius:50%;border:0;background:#8b9cff;color:#10131f;font-size:22px;cursor:pointer;z-index:9999;box-shadow:0 4px 16px #0006}
#cb-panel{position:fixed;right:20px;bottom:84px;width:380px;max-width:calc(100vw - 40px);height:500px;display:none;flex-direction:column;background:#161a26;color:#e7e9f2;border:1px solid #2c3247;border-radius:12px;z-index:9999;font:14px system-ui,sans-serif;box-shadow:0 8px 28px #0008}
#cb-panel.open{display:flex}#cb-head{padding:10px 14px;border-bottom:1px solid #2c3247;font-weight:600;display:flex;justify-content:space-between}
#cb-log{flex:1;overflow:auto;padding:10px;display:flex;flex-direction:column;gap:8px}
.cb-m{padding:8px 10px;border-radius:10px;max-width:90%;white-space:pre-wrap;line-height:1.4}.cb-u{align-self:flex-end;background:#3b4bd6}.cb-a{align-self:flex-start;background:#232940}
.cb-s{font-size:11px;color:#8d94b0;align-self:flex-start}#cb-quick{display:flex;gap:6px;padding:0 10px 6px;flex-wrap:wrap}
#cb-quick button{background:#232940;color:#cfd4ea;border:1px solid #2c3247;border-radius:14px;padding:3px 9px;font-size:12px;cursor:pointer;width:auto}
#cb-form{display:flex;gap:6px;padding:10px;border-top:1px solid #2c3247}#cb-in{flex:1;background:#0f1320;color:#e7e9f2;border:1px solid #2c3247;border-radius:8px;padding:8px}
#cb-send{background:#8b9cff;color:#10131f;border:0;border-radius:8px;padding:0 14px;font-weight:600;cursor:pointer;width:auto}`;
  document.head.appendChild(st);
  const btn=document.createElement("button");btn.id="cb-btn";btn.textContent="💬";btn.title="Ask the assistant";
  const panel=document.createElement("div");panel.id="cb-panel";
  panel.innerHTML=`<div id="cb-head"><span>CTI Assistant</span><span id="cb-x" style="cursor:pointer">✕</span></div><div id="cb-log"></div>
<div id="cb-quick"><button>Explain the whole project</button><button>What does each chapter show?</button><button>Check my PC for threats (read-only)</button><button>Run the script that checks for threats, then show the final project</button></div>
<form id="cb-form"><input id="cb-in" placeholder="Ask a question…" autocomplete="off"><button id="cb-send">Send</button></form>`;
  document.body.append(btn,panel);
  const log=panel.querySelector("#cb-log"),input=panel.querySelector("#cb-in");
  const add=(t,c)=>{const d=document.createElement("div");d.className="cb-m "+c;d.textContent=t;log.appendChild(d);log.scrollTop=log.scrollHeight;return d};
  const note=t=>{const d=document.createElement("div");d.className="cb-s";d.textContent=t;log.appendChild(d);log.scrollTop=log.scrollHeight};
  async function send(text){
    if(!text.trim())return;add(text,"cb-u");input.value="";const w=add("…","cb-a");
    try{
      const r=await fetch(`${API}/chat`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message:text,session_id:sid})});
      const j=await r.json();w.textContent=j.answer||j.error||"No answer";
      if(j.backend)note(`via ${j.backend} · memory: ${j.memory}${j.threats?" · read-only threat scan: "+j.threats.verdict:j.system?" · read-only system check":""}${j.llm_note?" · LLM: "+j.llm_note:""}`);
    }catch(e){w.textContent="Cannot reach server.py on "+API+". Start it with: python server.py"}
  }
  btn.onclick=()=>panel.classList.toggle("open");
  panel.querySelector("#cb-x").onclick=()=>panel.classList.remove("open");
  panel.querySelector("#cb-form").onsubmit=e=>{e.preventDefault();send(input.value)};
  panel.querySelectorAll("#cb-quick button").forEach(b=>b.onclick=()=>send(b.textContent));
  add("Hi! Ask me about any chapter, lab or API of this project, or ask me to check your PC for threats (read-only).","cb-a");
})();