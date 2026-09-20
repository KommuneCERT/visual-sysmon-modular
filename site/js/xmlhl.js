/* Tiny XML syntax highlighter + search-hit marker + textarea overlay editor.
   No dependencies; used by every XML view in the app. */
window.vsmXml = (function () {
  const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const ATTR = /([^\s=\/>]+)(\s*=\s*)("[^"]*"|'[^']*')|(\s+)|([^\s]+)/g;

  function tag(tok) {
    const m = /^(<\/?)([^\s\/>]+)([\s\S]*?)(\/?>)$/.exec(tok);
    if (!m) return '<span class="x-t">' + esc(tok) + '</span>';
    let out = '<span class="x-t">' + esc(m[1] + m[2]) + '</span>';
    let a;
    ATTR.lastIndex = 0;
    while ((a = ATTR.exec(m[3]))) {
      if (a[1] !== undefined) out += '<span class="x-a">' + esc(a[1]) + '</span>' + esc(a[2]) + '<span class="x-s">' + esc(a[3]) + '</span>';
      else out += esc(a[0]);
    }
    return out + '<span class="x-t">' + esc(m[4]) + '</span>';
  }

  function highlight(src) {
    const re = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[[\s\S]*?\]\]>|<\/?[^\s<>\/!?][^<>]*>/g;
    let out = '', i = 0, m;
    while ((m = re.exec(src))) {
      if (m.index > i) out += '<span class="x-x">' + esc(src.slice(i, m.index)) + '</span>';
      const t = m[0];
      if (t.startsWith('<!--')) out += '<span class="x-c">' + esc(t) + '</span>';
      else if (t.startsWith('<?') || t.startsWith('<![CDATA[')) out += '<span class="x-p">' + esc(t) + '</span>';
      else out += tag(t);
      i = m.index + t.length;
    }
    if (i < src.length) out += '<span class="x-x">' + esc(src.slice(i)) + '</span>';
    return out;
  }

  // Wrap every case-insensitive occurrence of each term in <mark>, walking text nodes only.
  function mark(root, terms) {
    terms = (terms || []).map(t => t.toLowerCase()).filter(Boolean);
    if (!terms.length) return;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    for (const node of nodes) {
      let text = node.nodeValue, lower = text.toLowerCase(), pos = 0;
      const frag = document.createDocumentFragment();
      let any = false;
      while (pos < text.length) {
        let best = -1, len = 0;
        for (const t of terms) { const i = lower.indexOf(t, pos); if (i !== -1 && (best === -1 || i < best)) { best = i; len = t.length; } }
        if (best === -1) break;
        frag.appendChild(document.createTextNode(text.slice(pos, best)));
        const m = document.createElement('mark'); m.textContent = text.slice(best, best + len); frag.appendChild(m);
        pos = best + len; any = true;
      }
      if (any) { frag.appendChild(document.createTextNode(text.slice(pos))); node.parentNode.replaceChild(frag, node); }
    }
  }

  // <pre class="vsm-xml-view" data-mark="term1 term2">escaped xml</pre>
  function initViews(root) {
    (root || document).querySelectorAll('pre.vsm-xml-view:not([data-hl])').forEach(pre => {
      pre.dataset.hl = '1';
      pre.innerHTML = highlight(pre.textContent);
      if (pre.dataset.mark) mark(pre, pre.dataset.mark.split(/\s+/));
    });
  }

  // textarea.vsm-xml-editor → highlighted <pre> behind a transparent textarea
  function initEditors(root) {
    (root || document).querySelectorAll('textarea.vsm-xml-editor:not([data-hl])').forEach(ta => {
      ta.dataset.hl = '1';
      const wrap = document.createElement('div'); wrap.className = 'vsm-xmled';
      const pre = document.createElement('pre'); pre.className = 'vsm-xmled-hl'; pre.setAttribute('aria-hidden', 'true');
      ta.parentNode.insertBefore(wrap, ta); wrap.appendChild(pre); wrap.appendChild(ta);
      const render = () => { pre.innerHTML = highlight(ta.value) + '\n'; };
      const sync = () => { pre.scrollTop = ta.scrollTop; pre.scrollLeft = ta.scrollLeft; };
      ta.addEventListener('input', render); ta.addEventListener('scroll', sync);
      ta.addEventListener('keydown', e => {          // Tab inserts two spaces instead of leaving the field
        if (e.key === 'Tab') { e.preventDefault(); const s = ta.selectionStart, en = ta.selectionEnd; ta.setRangeText('  ', s, en, 'end'); render(); }
      });
      render();
    });
  }

  function init(root) { initViews(root); initEditors(root); }
  window.addEventListener('DOMContentLoaded', () => {
    init(document);
    document.body.addEventListener('htmx:afterSwap', e => init(e.target));
    document.body.addEventListener('htmx:oobAfterSwap', e => init(e.target));
  });
  return { highlight, mark, init };
})();
