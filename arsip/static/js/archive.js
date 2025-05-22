document.addEventListener('DOMContentLoaded', function() {
  const deleteButtons = document.querySelectorAll('.delete-btn');
  const deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
  const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
  const deleteArchiveTitle = document.getElementById('deleteArchiveTitle');

  deleteButtons.forEach(button => {
    button.addEventListener('click', function() {
      const archiveId = this.getAttribute('data-id');
      const archiveTitle = this.getAttribute('data-title');
      
      deleteArchiveTitle.textContent = archiveTitle || 'Dokumen';
      confirmDeleteBtn.setAttribute('data-id', archiveId);
      deleteModal.show();
    });
  });

  confirmDeleteBtn.addEventListener('click', async function() {
    const archiveId = this.getAttribute('data-id');
    const csrfToken = document.querySelector('input[name="csrf_token"]').value;

    try {
      const response = await fetch(`/archives/delete/${archiveId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken
        }
      });
      const data = await response.json();
      if (!response.ok || !data.success) {
        throw new Error(data.error || 'Gagal menghapus arsip');
      }
      
      showAlert('success', data.message || 'Arsip berhasil dihapus');
      deleteModal.hide();
      setTimeout(() => window.location.reload(), 1500);
    } catch (error) {
      console.error('Delete error:', error);
      showAlert('danger', `Gagal menghapus arsip: ${error.message}`);
    }
  });

  function showAlert(type, message) {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.style.position = 'fixed';
    alert.style.top = '20px';
    alert.style.left = '50%';
    alert.style.transform = 'translateX(-50%)';
    alert.style.zIndex = '2000';
    alert.style.maxWidth = '600px';
    alert.innerHTML = `
      ${message}
      <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    document.body.appendChild(alert);
    setTimeout(() => {
      alert.classList.remove('show');
      setTimeout(() => alert.remove(), 150);
    }, 5000);
  }
});