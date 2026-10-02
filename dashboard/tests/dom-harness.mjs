import { readFile } from 'node:fs/promises';

// Small DOM surface for the dashboard's browser integration tests. No HTML
// interpreter is used for telemetry: textContent remains an ordinary text node.
class TestNode {
  constructor() {
    this.children = [];
    this.parentNode = null;
  }

  append(...nodes) {
    for (const value of nodes) {
      const child = value instanceof TestNode ? value : new TestText(String(value));
      child.parentNode = this;
      this.children.push(child);
    }
  }

  replaceChildren(...nodes) {
    for (const child of this.children) child.parentNode = null;
    this.children = [];
    this.append(...nodes);
  }

  get textContent() {
    return this.children.map((child) => child.textContent).join('');
  }

  set textContent(value) {
    this.replaceChildren(new TestText(String(value)));
  }
}

class TestText extends TestNode {
  constructor(value) {
    super();
    this.value = value;
  }

  get textContent() { return this.value; }
  set textContent(value) { this.value = String(value); }
}

class TestElement extends TestNode {
  constructor(tag) {
    super();
    this.tagName = tag.toUpperCase();
    this.attributes = new Map();
    this.listeners = new Map();
    this.id = '';
    this.className = '';
    this.value = '';
    this.hidden = false;
    this.disabled = false;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
    if (name === 'id') this.id = String(value);
    if (name === 'class') this.className = String(value);
    if (name === 'hidden' || name === 'disabled') this[name] = true;
    if (name === 'value') this.value = String(value);
  }

  getAttribute(name) {
    if (name === 'id') return this.id || null;
    if (name === 'class') return this.className || null;
    return this.attributes.get(name) ?? null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
    if (name === 'hidden' || name === 'disabled') this[name] = false;
  }

  addEventListener(type, callback) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(callback);
    this.listeners.set(type, listeners);
  }

  async trigger(type) {
    const event = { type, target: this, preventDefault() {} };
    await Promise.all((this.listeners.get(type) ?? []).map((listener) => listener(event)));
  }

  focus() { this.focused = true; }

  querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }

  querySelectorAll(selector) {
    const selectors = selector.split(',').map((part) => part.trim());
    const matches = (element) => selectors.some((part) => {
      if (part.startsWith('#')) return element.id === part.slice(1);
      if (part.startsWith('.')) return element.className.split(/\s+/).includes(part.slice(1));
      return element.tagName.toLowerCase() === part.toLowerCase();
    });
    const results = [];
    const walk = (node) => {
      for (const child of node.children) {
        if (child instanceof TestElement && matches(child)) results.push(child);
        walk(child);
      }
    };
    walk(this);
    return results;
  }
}

function parseStaticHtml(html) {
  const document = new TestElement('document');
  document.createElement = (tag) => new TestElement(tag);
  document.createTextNode = (value) => new TestText(String(value));
  const stack = [document];
  const voidTags = new Set(['meta', 'link', 'input', 'br', 'hr', 'img']);
  for (const match of html.matchAll(/<\/?([a-z][a-z0-9-]*)([^>]*)>|([^<]+)/gi)) {
    if (!match[1]) {
      stack.at(-1).append(new TestText(match[3]));
      continue;
    }
    const tag = match[1].toLowerCase();
    if (match[0].startsWith('</')) {
      if (stack.at(-1).tagName.toLowerCase() === tag) stack.pop();
      continue;
    }
    const element = document.createElement(tag);
    for (const attribute of match[2].matchAll(/([\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s]+)))?/g)) {
      element.setAttribute(attribute[1], attribute[2] ?? attribute[3] ?? attribute[4] ?? '');
    }
    stack.at(-1).append(element);
    if (!voidTags.has(tag)) stack.push(element);
  }
  return document;
}

export function response(status, data) {
  return { status, ok: status >= 200 && status < 300, json: async () => structuredClone(data) };
}

export function deferred() {
  let resolve;
  const promise = new Promise((complete) => { resolve = complete; });
  return { promise, resolve };
}

export async function settle() {
  // Fetch and response.json each schedule a promise continuation; yielding to
  // the event loop lets a complete dashboard navigation finish.
  await new Promise((resolve) => setImmediate(resolve));
}

let imports = 0;

export async function startDashboard(handler, hash = '#/alerts') {
  const saved = Object.fromEntries(['document', 'window', 'Node', 'fetch'].map((key) => [key, globalThis[key]]));
  const document = parseStaticHtml(await readFile(new URL('../index.html', import.meta.url), 'utf8'));
  const window = new TestElement('window');
  let currentHash = hash;
  window.location = {
    protocol: 'http:', hostname: '127.0.0.1',
    get hash() { return currentHash; },
    set hash(value) {
      if (value === currentHash) return;
      currentHash = value;
      queueMicrotask(() => { void window.trigger('hashchange'); });
    },
  };
  const calls = [];
  Object.assign(globalThis, {
    document, window, Node: TestNode,
    fetch: async (path, options = {}) => {
      const call = { path, ...options, method: options.method ?? 'GET' };
      calls.push(call);
      return handler(call);
    },
  });
  try {
    await import(`../assets/app.js?test=${++imports}`);
  } catch (error) {
    Object.assign(globalThis, saved);
    throw error;
  }
  return {
    document, window, calls,
    get: (selector) => document.querySelector(selector),
    async login() {
      document.querySelector('#username').value = 'test-admin';
      document.querySelector('#password').value = 'development-password';
      await document.querySelector('#login-form').trigger('submit');
      await settle();
    },
    async navigate(nextHash) {
      window.location.hash = nextHash;
      await settle();
    },
    restore() { Object.assign(globalThis, saved); },
  };
}
