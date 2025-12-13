/* Shared Table of Contents Logic for Hexo Posts/Pages */

document.addEventListener('DOMContentLoaded', () => {
    // Only run if we are NOT on a GitBook page (GitBook.js handles those)
    if (document.body.classList.contains('gitbook-page')) return;

    const contentBody = document.querySelector('.mypage'); // Selector from article.ejs
    const tocNav = document.getElementById('toc-nav');
    const tocContainer = document.getElementById('content-toc');

    if (!contentBody || !tocNav || !tocContainer) return;

    // Generate TOC
    const headers = contentBody.querySelectorAll('h1, h2, h3'); // Posts might use H1 too

    if (!headers.length) {
        tocContainer.style.display = 'none';
        return;
    }

    tocNav.innerHTML = '';
    tocContainer.style.display = 'block';

    headers.forEach((header, index) => {
        // Create ID if missing
        if (!header.id) {
            header.id = 'heading-' + index;
        }

        const link = document.createElement('a');
        link.className = `toc-link toc-${header.tagName.toLowerCase()}`;
        link.href = '#' + header.id;
        link.textContent = header.textContent;

        link.addEventListener('click', (e) => {
            e.preventDefault();
            header.scrollIntoView({ behavior: 'smooth' });
            // Update active state
            tocNav.querySelectorAll('.toc-link').forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            // Push state for history
            history.pushState(null, null, '#' + header.id);
        });

        tocNav.appendChild(link);
    });

    // Scroll Spy
    const observerOptions = {
        root: null,
        rootMargin: '-100px 0px -66%',
        threshold: 0
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const id = entry.target.id;
                tocNav.querySelectorAll('.toc-link').forEach(link => {
                    link.classList.remove('active');
                    if (link.getAttribute('href') === '#' + id) {
                        link.classList.add('active');
                    }
                });
            }
        });
    }, observerOptions);

    headers.forEach(header => observer.observe(header));
});
