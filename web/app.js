let latestEntries=[];
const $=s=>document.querySelector(s);
const message=(s)=>$('#message').textContent=s;
$('#scan').addEventListener('submit',async e=>{
 e.preventDefault();message('Scanning accessible files…');
 try{
  const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({source:$('#source').value})});
  const d=await r.json();if(!r.ok)throw Error(d.detail||'Scan failed');
  latestEntries=d.entries;$('#results').hidden=false;
  $('#files').textContent=d.files_scanned;$('#media').textContent=d.media_count;$('#backups').textContent=d.backup_candidates;$('#dupes').textContent=d.duplicates.length;
  renderEntries();await loadSnapshots();message(`Scan complete. ${d.errors.length} warnings.`);
 }catch(err){message(err.message)}
});
function renderEntries(){
 const q=$('#filter').value.toLowerCase(),body=$('#entries');body.replaceChildren();
 latestEntries.filter(x=>x.kind==='media'&&x.name.toLowerCase().includes(q)).forEach(item=>{
  const tr=document.createElement('tr');
  const check=document.createElement('input');check.type='checkbox';check.className='pick';check.value=item.path;check.setAttribute('aria-label','Select '+item.name);
  const td0=document.createElement('td');td0.append(check);tr.append(td0);
  [item.mime||'media',item.name,`${item.size} bytes`,item.sha256].forEach((v,i)=>{const td=document.createElement('td');td.textContent=v;if(i===3)td.className='hash';tr.append(td)});
  const td=document.createElement('td');
  if(item.mime){const b=document.createElement('button');b.className='preview-btn';b.textContent='Preview';b.addEventListener('click',()=>showPreview(item));td.append(b)}else td.textContent='Not previewable';
  tr.append(td);body.append(tr);
 });
}
$('#filter').addEventListener('input',renderEntries);
async function showPreview(item){
 const box=$('#preview'),body=$('#previewBody');body.replaceChildren();box.hidden=false;
 const url='/api/preview?path='+encodeURIComponent(item.path);
 let el;
 if(item.mime.startsWith('image/')){el=document.createElement('img');el.alt=item.name;el.className='media-preview';}
 else if(item.mime.startsWith('video/')){el=document.createElement('video');el.controls=true;el.className='media-preview'}
 else {el=document.createElement('audio');el.controls=true}
 el.src=url;body.append(el);const p=document.createElement('p');p.textContent=item.name;body.append(p);box.scrollIntoView({behavior:'smooth'});
}
$('#closePreview').addEventListener('click',()=>{$('#preview').hidden=true;$('#previewBody').replaceChildren()});
async function loadSnapshots(){
 const d=await fetch('/api/snapshots').then(r=>r.json());
 for(const id of ['old','new']){const sel=$('#'+id);sel.replaceChildren();d.snapshots.forEach(s=>{const o=document.createElement('option');o.value=s.path;o.textContent=s.name;sel.append(o)})}
 if(d.snapshots.length>1)$('#new').selectedIndex=d.snapshots.length-1;
}
$('#compare').addEventListener('click',async()=>{
 const out=$('#comparison');out.textContent='Comparing…';
 try{const r=await fetch('/api/compare',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old:$('#old').value,new:$('#new').value})});const d=await r.json();if(!r.ok)throw Error(d.detail);
 out.replaceChildren();const wrap=document.createElement('div');wrap.className='comparison-stats';
 Object.entries(d.summary).forEach(([k,v])=>{const s=document.createElement('span');s.textContent=`${k}: ${v}`;wrap.append(s)});out.append(wrap);
 }catch(e){out.textContent=e.message}
});
$('#export').addEventListener('click',async()=>{
 const paths=[...document.querySelectorAll('.pick:checked')].map(x=>x.value);
 if(!paths.length){$('#exportmsg').textContent='Select at least one media file.';return}
 if(!$('#destination').value.trim()){ $('#exportmsg').textContent='Enter a destination folder.';return}
 $('#exportmsg').textContent='Copying and verifying SHA-256…';
 try{const r=await fetch('/api/export',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paths,destination:$('#destination').value})});const d=await r.json();if(!r.ok)throw Error(d.detail);
 $('#exportmsg').textContent=`Verified ${d.verified_count} of ${d.results.length} selected files. Review errors in any unverified results.`;
 }catch(e){$('#exportmsg').textContent=e.message}
});
$('#lang').addEventListener('change',async e=>{const t=await fetch('/api/i18n/'+e.target.value).then(r=>r.json());$('#title').textContent=t.title;$('#scan button').textContent=t.scan;message(t.privacy)});
