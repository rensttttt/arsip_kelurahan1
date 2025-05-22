// =======================
// DATA LOADING FUNCTIONS
// =======================

function loadUserProfile() {
    console.log('Memuat data profil...');
    // Implementasi AJAX/Fetch untuk mengambil data dari API
}

function loadUserStats() {
    console.log('Memuat statistik akun...');
    // Implementasi AJAX/Fetch untuk mengambil data dari API
}

function loadRecentActivity() {
    console.log('Memuat aktivitas terakhir...');
    // Implementasi AJAX/Fetch untuk mengambil data dari API
}

function loadActiveSessions() {
    console.log('Memuat sesi aktif...');
    // Implementasi AJAX/Fetch untuk mengambil data dari API
}

// =======================
// PROFILE EDIT FUNCTIONS
// =======================

function enableProfileEditing() {
    console.log('Mengaktifkan mode edit profil...');
    // Logika untuk membuat field editable
}

function cancelProfileEditing() {
    console.log('Membatalkan edit profil...');
    // Logika untuk mengembalikan ke mode read-only
}

function saveProfileChanges(e) {
    e.preventDefault();
    console.log('Menyimpan perubahan profil...');
    // Implementasi AJAX/Fetch untuk menyimpan data ke server
}

// =======================
// AUTHENTICATION FUNCTIONS
// =======================

function logoutUser() {
    console.log('Logout pengguna...');
    // Implementasi logout
}

function logoutAllDevices() {
    console.log('Logout dari semua perangkat...');
    // Implementasi logout semua sesi
}

function checkAuthStatus() {
    console.log('Memeriksa status autentikasi...');
    // Implementasi pengecekan status login
}

// =======================
// AVATAR HANDLING FUNCTIONS
// =======================

function previewAvatar(e) {
    const file = e.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function (e) {
            document.getElementById('avatarPreview').src = e.target.result;
        };
        reader.readAsDataURL(file);
    }
}

function uploadAvatar(e) {
    e.preventDefault();
    console.log('Mengunggah avatar...');
    // Implementasi AJAX/Fetch untuk mengunggah gambar
}

// =======================
// PASSWORD CHANGE FUNCTION
// =======================

function changePassword(e) {
    e.preventDefault();
    console.log('Mengubah password...');
    // Implementasi AJAX/Fetch untuk mengubah password
}

// =======================
// UTILITY FUNCTIONS
// =======================

// Alert generator
function showAlert(type, message) {
    const alertContainer = document.getElementById('alertContainer');
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.setAttribute('role', 'alert');
    alertDiv.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    alertContainer.appendChild(alertDiv);

    setTimeout(() => {
        const bsAlert = new bootstrap.Alert(alertDiv);
        bsAlert.close();
    }, 5000);
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Get color based on activity type
function getActivityColor(type) {
    const colors = {
        login: 'primary',
        upload: 'success',
        download: 'info',
        delete: 'danger',
        comment: 'warning',
        profile: 'secondary'
    };
    return colors[type] || 'primary';
}

// Get icon class based on activity type
function getActivityIcon(type) {
    const icons = {
        login: 'fa-sign-in-alt',
        upload: 'fa-upload',
        download: 'fa-download',
        delete: 'fa-trash',
        comment: 'fa-comment',
        profile: 'fa-user-edit'
    };
    return icons[type] || 'fa-info-circle';
}
