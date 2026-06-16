(() => {
  const modal = document.getElementById('verify-modal');
  const openButtons = document.querySelectorAll('[data-open-verify]');
  const closeButtons = document.querySelectorAll('[data-close-verify]');
  const authLinks = document.querySelectorAll('[data-auth-link]');
  const hostLabel = document.querySelector('[data-current-host]');
  const motionAllowed = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let lastFocused = null;

  const query = new URLSearchParams(window.location.search);
  const forwarded = new URLSearchParams();
  ['guildId', 'prompt', 'mode'].forEach((key) => {
    if (query.has(key)) forwarded.set(key, query.get(key));
  });
  const authPath = `/auth/discord${forwarded.toString() ? `?${forwarded.toString()}` : ''}`;

  authLinks.forEach((link) => {
    link.setAttribute('href', authPath);
  });

  if (hostLabel) {
    hostLabel.textContent = window.location.host || 'este site';
  }

  const closeModal = () => {
    if (!modal || modal.getAttribute('aria-hidden') === 'true') return;
    modal.setAttribute('aria-hidden', 'true');
    modal.classList.remove('is-open');
    document.body.classList.remove('modal-open');
    if (lastFocused && typeof lastFocused.focus === 'function') lastFocused.focus();
  };

  const openModal = (event) => {
    if (!modal) return;
    event.preventDefault();
    lastFocused = document.activeElement;
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('is-open');
    document.body.classList.add('modal-open');
    const continueButton = modal.querySelector('[data-auth-link]');
    if (continueButton) continueButton.focus();
  };

  openButtons.forEach((button) => button.addEventListener('click', openModal));
  closeButtons.forEach((button) => button.addEventListener('click', closeModal));

  if (modal) {
    modal.addEventListener('click', (event) => {
      if (event.target === modal) closeModal();
    });
  }

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeModal();
  });

  document.querySelectorAll('[data-close-preview]').forEach((button) => {
    button.addEventListener('click', () => {
      const panel = button.closest('.discord-panel');
      if (!panel) return;
      panel.classList.remove('panel-tap');
      requestAnimationFrame(() => panel.classList.add('panel-tap'));
    });
  });

  if (motionAllowed) {
    const stage = document.querySelector('.brand-stage');
    window.addEventListener('pointermove', (event) => {
      if (!stage) return;
      const x = (event.clientX / window.innerWidth - 0.5).toFixed(3);
      const y = (event.clientY / window.innerHeight - 0.5).toFixed(3);
      stage.style.setProperty('--tilt-x', `${Number(y) * -8}deg`);
      stage.style.setProperty('--tilt-y', `${Number(x) * 8}deg`);
    }, { passive: true });
  }
})();
