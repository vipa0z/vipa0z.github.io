// Theme Toggle Script
(function() {
    'use strict';

    function initThemeSwitcher() {
        const container = document.createElement('div');
        container.id = 'theme-switcher-container';

        const modeBtn = document.createElement('button');
        modeBtn.id = 'theme-toggle';
        modeBtn.textContent = '🌙 Dark';

        modeBtn.addEventListener('click', function() {
            const isLight = document.body.classList.toggle('light-theme');
            modeBtn.textContent = isLight ? '☀️ Light' : '🌙 Dark';
            localStorage.setItem('theme-preference', isLight ? 'light' : 'dark');
        });

        container.appendChild(modeBtn);
        document.body.appendChild(container);

        // Load preferences
        const savedTheme = localStorage.getItem('theme-preference') || 'dark';
        
        if (savedTheme === 'light') {
            document.body.classList.add('light-theme');
            modeBtn.textContent = '☀️ Light';
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initThemeSwitcher);
    } else {
        initThemeSwitcher();
    }
})();

