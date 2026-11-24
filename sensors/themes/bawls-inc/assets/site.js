// Bawls Inc. decoy theme. Cosmetic only: the phone menu, the footer year, forms
// and a support chat that never leave the browser (the chat's replies are
// canned, below; a sensor test keeps network calls out of this file), the
// counting-up figures, and a little motion. Nothing is hidden unless
// this script runs, and visitors who ask for reduced motion get none of it.
document.addEventListener('DOMContentLoaded', () => {
  const nav = document.querySelector('.nav');
  const burger = document.querySelector('.burger');
  if (nav && burger) {
    burger.addEventListener('click', () => burger.setAttribute('aria-expanded', nav.classList.toggle('open')));
  }

  const year = document.getElementById('yr');
  if (year) year.textContent = new Date().getFullYear();

  // Every form is a demo: it shows its message and sends nothing.
  document.querySelectorAll('form[data-demo]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      form.reset();
      const message = form.querySelector('.form-msg');
      if (message) message.hidden = false;
    });
  });

  if (nav) {
    const shade = () => nav.classList.toggle('scrolled', window.scrollY > 8);
    window.addEventListener('scroll', shade, { passive: true });
    shade();
  }

  supportChat();

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || !('IntersectionObserver' in window)) return;

  // Fade sections up as they scroll in. Anything already on screen is left alone.
  const observer = new IntersectionObserver((entries) => {
    entries.filter((entry) => entry.isIntersecting).forEach(({ target }) => {
      target.classList.add('in');
      observer.unobserve(target);
      target.querySelectorAll('.n, .result').forEach(countUp);
    });
  }, { rootMargin: '0px 0px -8% 0px' });

  document.querySelectorAll('.sec .card, .sec .center, .stat, .callout, .cta-band, .split > *, .timeline li, .badges')
    .forEach((el) => {
      if (el.getBoundingClientRect().top < window.innerHeight) return;
      el.style.transitionDelay = `${([...el.parentElement.children].indexOf(el) % 4) * 80}ms`;
      el.classList.add('reveal');
      observer.observe(el);
    });
});

// The support chat: always "after hours". It lives entirely in this page.
// Nothing a visitor types is sent anywhere or stored; it vanishes on reload.
const CHAT_GREETING = 'Hi there! Welcome to Bawls Inc. Ask us anything about The Ball&trade;, BallOps&trade; or your order.';
const CHAT_REPLIES = [
  'Thanks for your message! You&rsquo;ve reached Bawls Inc. after hours. Our sphere specialists are in Monday to Friday, 9&ndash;5 Pacific, and roll back to every enquiry within one rolling day. In the meantime, the <a href="/support">Help Center</a> answers most questions.',
  'Our team is still away from their desks. For anything urgent, <a href="/support/sign-in">sign-in help</a> and <a href="/status">system status</a> are available around the clock, or you can <a href="/contact">contact us</a>.',
  'We&rsquo;re still after hours, we&rsquo;re afraid. The ball, however, is always available.',
];
const CHAT_HTML = `
<div class="chat">
  <div class="chat-teaser" hidden>
    <button type="button" class="chat-teaser-close" aria-label="Dismiss">&times;</button>
    <p><b>Questions about The Ball&trade;?</b> Chat with a sphere specialist.</p>
  </div>
  <section class="chat-panel" role="dialog" aria-label="Chat with Bawls support" hidden>
    <header class="chat-head">
      <span class="chat-avatar" aria-hidden="true"></span>
      <div><b>Bawls Support</b><small class="chat-status">Typically replies in a few minutes</small></div>
      <button type="button" class="chat-close" aria-label="Close chat">&times;</button>
    </header>
    <div class="chat-log" role="log" aria-live="polite"></div>
    <form class="chat-form" autocomplete="off">
      <label class="sr" for="chat-input">Your message</label>
      <input id="chat-input" name="message" placeholder="Type your message&hellip;" maxlength="500" required>
      <button type="submit" class="chat-send" aria-label="Send"><svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true"><path d="M3 20l18-8L3 4v6l12 2-12 2z"/></svg></button>
    </form>
    <p class="chat-foot">Powered by RollChat&trade;</p>
  </section>
  <button type="button" class="chat-launch" aria-label="Chat with support" aria-expanded="false"><svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1-4.6A8 8 0 1 1 21 12z"/></svg></button>
</div>`;

function supportChat() {
  document.body.insertAdjacentHTML('beforeend', CHAT_HTML);
  const chat = document.querySelector('.chat');
  const launcher = chat.querySelector('.chat-launch');
  const panel = chat.querySelector('.chat-panel');
  const teaser = chat.querySelector('.chat-teaser');
  const log = chat.querySelector('.chat-log');
  const form = chat.querySelector('.chat-form');
  const input = form.querySelector('input');
  let replies = 0;
  let pending = null;

  // Visitor text goes in as text; our own lines are fixed HTML (for their links).
  const say = (who, content, isHtml) => {
    const message = document.createElement('div');
    message.className = `msg ${who}`;
    message[isHtml ? 'innerHTML' : 'textContent'] = content;
    log.append(message);
    log.scrollTop = log.scrollHeight;
    return message;
  };

  const open = (show) => {
    panel.hidden = !show;
    teaser.hidden = true;
    launcher.setAttribute('aria-expanded', show);
    launcher.classList.remove('unread');
    if (!show) return launcher.focus();
    if (!log.children.length) say('them', CHAT_GREETING, true);
    input.focus();
  };

  launcher.addEventListener('click', () => open(panel.hidden));
  chat.querySelector('.chat-close').addEventListener('click', () => open(false));
  panel.addEventListener('keydown', (event) => event.key === 'Escape' && open(false));
  teaser.addEventListener('click', (event) => {
    if (event.target.closest('.chat-teaser-close')) teaser.hidden = true;
    else open(true);
  });

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const text = input.value.trim();
    if (!text) return;
    say('me', text);
    input.value = '';
    if (pending) return;   // one answer covers a burst of messages
    const typing = say('them typing', '<i></i><i></i><i></i><span class="sr">Support is typing</span>', true);
    pending = setTimeout(() => {
      typing.remove();
      pending = null;
      say('them', CHAT_REPLIES[Math.min(replies++, CHAT_REPLIES.length - 1)], true);
      chat.classList.add('away');
      chat.querySelector('.chat-status').textContent = 'Away · back 9 AM Pacific';
      if (panel.hidden) launcher.classList.add('unread');
    }, 2500 + Math.random() * 2000);
  });

  // A one-time nudge per visit. Storage can be off; then it just shows each page.
  let nudged = false;
  try { nudged = sessionStorage.getItem('bawls-chat') === 'nudged'; } catch (error) { /* storage blocked */ }
  if (!nudged) {
    setTimeout(() => {
      if (!panel.hidden) return;
      teaser.hidden = false;
      try { sessionStorage.setItem('bawls-chat', 'nudged'); } catch (error) { /* storage blocked */ }
    }, 6000);
  }
}

// Count a figure such as "4,000+" or "99.99%" up from zero, keeping its format.
function countUp(el) {
  const match = /^(\D*)([\d,]*\.?\d+)(.*)$/.exec(el.textContent.trim());
  if (!match) return;
  const [, prefix, figure, suffix] = match;
  const target = parseFloat(figure.replace(/,/g, ''));
  const decimals = (figure.split('.')[1] || '').length;
  const format = (value) => value.toLocaleString('en-US', {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals,
    useGrouping: figure.includes(','),
  });
  const start = performance.now();
  const step = (now) => {
    const progress = Math.min(1, (now - start) / 1200);
    el.textContent = prefix + format(target * (1 - (1 - progress) ** 3)) + suffix;
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
