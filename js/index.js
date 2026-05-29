// Index page - tactic card filter (external file for CSP compliance)
document.getElementById('tactic-search')?.addEventListener('input', function () {
  const q = this.value.toLowerCase().trim();
  document.querySelectorAll('.tactic-card').forEach(card => {
    const text = (card.textContent + ' ' + (card.dataset.tags || '')).toLowerCase();
    card.style.display = !q || text.includes(q) ? '' : 'none';
  });
});
