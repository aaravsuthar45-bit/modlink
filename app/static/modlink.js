(function(){
var P={asterisk:'<path d="M12 3v18M4.2 7.5l15.6 9M4.2 16.5l15.6-9"/>',bolt:'<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',shield:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',key:'<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 21 2m-4 4 3 3"/>',log:'<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',check:'<circle cx="12" cy="12" r="10"/><path d="m8 12 3 3 5-6"/>',alert:'<circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/>',plus:'<path d="M12 5v14M5 12h14"/>',menu:'<path d="M4 6h16M4 12h16M4 18h16"/>',x:'<path d="M18 6 6 18M6 6l12 12"/>',mail:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>'};
var D='M107.7,8.07A105.15,105.15,0,0,0,81.47,0a72.06,72.06,0,0,0-3.36,6.83A97.68,97.68,0,0,0,49,6.83,72.37,72.37,0,0,0,45.64,0,105.89,105.89,0,0,0,19.39,8.09C2.79,32.65-1.71,56.6.54,80.21h0A105.73,105.73,0,0,0,32.71,96.36,77.7,77.7,0,0,0,39.6,85.25a68.42,68.42,0,0,1-10.85-5.18c.91-.66,1.8-1.34,2.66-2a75.57,75.57,0,0,0,64.32,0c.87.71,1.76,1.39,2.66,2a68.68,68.68,0,0,1-10.87,5.19,77,77,0,0,0,6.89,11.1A105.25,105.25,0,0,0,126.6,80.22h0C129.24,52.84,122.09,29.11,107.7,8.07ZM42.45,65.69C36.18,65.69,31,60,31,53s5-12.74,11.43-12.74S54,45.91,53.89,53,48.84,65.69,42.45,65.69Zm42.24,0C78.41,65.69,73.25,60,73.25,53s5-12.74,11.44-12.74S96.23,45.91,96.12,53,91.08,65.69,84.69,65.69Z';
function svg(n){return n==='discord'?'<svg class="ic" style="width:22px;fill:currentColor;stroke:none" viewBox="0 0 127.14 96.36" aria-hidden="true"><path d="'+D+'"/></svg>':'<svg class="ic" viewBox="0 0 24 24" aria-hidden="true">'+(P[n]||'')+'</svg>'}
function icons(r){(r||document).querySelectorAll('[data-i]:empty').forEach(function(e){e.innerHTML=svg(e.dataset.i)})}
window.ML={svg:svg,icons:icons};
document.addEventListener('DOMContentLoaded',function(){
icons();
if(location.protocol==='file:')document.querySelectorAll('a[href^="/"]').forEach(function(a){var h=a.getAttribute('href');if(h.indexOf('/auth')===0)return;a.setAttribute('href',h==='/'?'index.html':h.slice(1)+'.html')});
document.querySelectorAll('[data-year]').forEach(function(e){e.textContent=new Date().getFullYear()});
var b=document.querySelector('.nav-toggle'),n=document.getElementById('nav');
if(b&&n){
function set(o){n.classList.toggle('open',o);b.setAttribute('aria-expanded',o);b.firstElementChild.innerHTML=svg(o?'x':'menu')}
b.addEventListener('click',function(){set(!n.classList.contains('open'))});
document.addEventListener('keydown',function(e){if(e.key==='Escape')set(false)});
n.addEventListener('click',function(e){if(e.target.closest('a'))set(false)});
window.addEventListener('resize',function(){if(innerWidth>760)set(false)});}
var box=document.getElementById('notice');
if(box){
var q=new URLSearchParams(location.search),er=q.get('error'),ok=q.get('success');
var M={access_denied:'Discord authorization was cancelled. Log in again to continue.',no_admin_guilds:'No servers found where you have Administrator or Manage Server access.',invalid_state:'Your login session expired. Please try again.'};
if(er||ok){
box.className='notice '+(er?'err':'ok');
box.firstElementChild.innerHTML=svg(er?'alert':'check');
box.lastElementChild.textContent=er?(M[er]||'Something went wrong while connecting to Discord. Please try again.'):(M[ok]||'Connected successfully.');
box.hidden=false;}}
});})();
