document.addEventListener('DOMContentLoaded', function() {
    // Language dropdown functionality
    const dropdowns = document.querySelectorAll('.language-dropdown');
    
    dropdowns.forEach(dropdown => {
        const toggle = dropdown.querySelector('.dropdown-toggle');
        
        toggle.addEventListener('click', function(e) {
            e.stopPropagation();
            const isExpanded = dropdown.getAttribute('aria-expanded') === 'true';
            dropdown.setAttribute('aria-expanded', !isExpanded);
            
            // Close other open dropdowns
            document.querySelectorAll('.language-dropdown').forEach(other => {
                if (other !== dropdown) {
                    other.setAttribute('aria-expanded', 'false');
                }
            });
        });
        
        // Handle language selection
        dropdown.querySelectorAll('.dropdown-menu a').forEach(item => {
            item.addEventListener('click', function(e) {
                e.preventDefault();
                const lang = this.getAttribute('data-lang');
                
                fetch('/set_language', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({language: lang})
                }).then(response => {
                    if (response.ok) {
                        window.location.reload();
                    }
                }).catch(error => {
                    console.error('Language change error:', error);
                });
            });
        });
    });
    
    // Close dropdown when clicking outside
    document.addEventListener('click', function() {
        document.querySelectorAll('.language-dropdown').forEach(dropdown => {
            dropdown.setAttribute('aria-expanded', 'false');
        });
    });
});
