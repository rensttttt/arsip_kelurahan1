document.addEventListener('DOMContentLoaded', () => {
    const searchForm = document.getElementById('searchForm');
    const searchInput = document.getElementById('searchInput');
    const resultCount = document.getElementById('resultCount');

    // Validate required DOM elements
    if (!searchForm || !searchInput) {
        console.error('Search elements not found');
        return;
    }

    // Function to validate and provide feedback
    const validateSearch = (query) => {
        query = query.trim();
        if (query.length < 3 && query.length > 0) {
            searchInput.classList.add('is-invalid');
            let feedback = searchInput.nextElementSibling;
            if (!feedback || !feedback.classList.contains('invalid-feedback')) {
                feedback = document.createElement('div');
                feedback.className = 'invalid-feedback';
                searchInput.parentNode.appendChild(feedback);
            }
            feedback.textContent = 'Masukkan setidaknya 3 karakter untuk pencarian.';
            return false;
        } else {
            searchInput.classList.remove('is-invalid');
            const feedback = searchInput.nextElementSibling;
            if (feedback && feedback.classList.contains('invalid-feedback')) {
                feedback.remove();
            }
            return true;
        }
    };

    // Debounced input validation (300ms)
    let debounceTimer;
    searchInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            validateSearch(searchInput.value);
        }, 300);
    });

    // Form submission validation
    searchForm.addEventListener('submit', (e) => {
        if (!validateSearch(searchInput.value)) {
            e.preventDefault();
        }
    });

    // Update result count accessibility
    if (resultCount) {
        resultCount.setAttribute('aria-live', 'polite');
    }
});