'use strict';

hexo.extend.helper.register('format_kali_code', function(html) {
  // This processes the rendered HTML and adds Kali prompt prefix
  const figureRegex = /<figure class="highlight (?:shell|bash|sh|plaintext)"><table><tbody><tr><td class="gutter">[\s\S]*?<\/td><td class="code"><pre>([\s\S]*?)<\/pre><\/td><\/tr><\/tbody><\/table><\/figure>/g;
  
  return html.replace(figureRegex, function(match) {
    if (match.includes('kali-user')) return match; // Already processed
    
    const codeMatch = match.match(/<pre>([\s\S]*?)<\/pre>/);
    if (!codeMatch) return match;
    
    let codeHtml = codeMatch[1];
    const lines = codeHtml.split(/<br\s*\/?>/);
    
    const prefixedLines = lines.map(line => {
      const textContent = line.replace(/<[^>]+>/g, '').trim();
      if (textContent && !textContent.includes('vipa0z')) {
        return `<span class="kali-user">vipa0z</span> $ ${line}`;
      }
      return line;
    });
    
    const newCode = prefixedLines.join('<br>');
    return match.replace(/(<pre>)([\s\S]*?)(<\/pre>)/, `$1${newCode}$3`);
  });
});