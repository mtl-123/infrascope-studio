(()=>{
const root=document.getElementById('infra-observer'),content=root.querySelector('#io-content');
let busy=false;
function enhance(){if(busy)return;busy=true;const h=content.querySelector('h2');if(h){const title=h.textContent;content.dataset.studioTitle=title;root.querySelector('#studio-breadcrumb').textContent=title;if(!h.closest('.page-heading')){const sub=h.nextElementSibling,wrap=document.createElement('div'),left=document.createElement('div');wrap.className='page-heading';h.before(wrap);left.append(h);if(sub?.classList.contains('muted'))left.append(sub);wrap.append(left);}}busy=false;}
new MutationObserver(()=>{const h=content.querySelector('h2');if(h&&(h.textContent!==content.dataset.studioTitle||!h.closest('.page-heading')))enhance();}).observe(content,{childList:true,subtree:true});enhance();
root.querySelectorAll('[data-icon]').forEach(el=>el.innerHTML=window.InfraWorkspace.icon(el.dataset.icon));
})();
