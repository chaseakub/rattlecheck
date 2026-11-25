'use strict';

const byId = (id) => document.getElementById(id);
const tokens = /(--.*$|'(?:''|[^'])*'|\b(?:after|alter|begin|by|check|create|declare|definer|each|enable|end|execute|for|from|function|grant|insert|into|language|level|on|or|policy|replace|return|returns|revoke|row|security|select|set|table|to|trigger|update|using|values|with)\b)/gi;
let example;
let originalAnswer;
let feedbackTimer;

function showCode(id, file) {
  byId(id + '-file').textContent = file.file;
  const lines = document.createDocumentFragment();
  for (const [index, line] of file.sql.trimEnd().split(/\r?\n/).entries()) {
    const row = document.createElement('span');
    row.className = 'sql-line';
    const number = document.createElement('span');
    number.className = 'line-number';
    number.setAttribute('aria-hidden', 'true');
    number.textContent = String(index + 1);
    const content = document.createElement('span');
    content.className = 'sql-text';
    let last = 0;
    for (const match of line.matchAll(tokens)) {
      const fragment = document.createElement('span');
      const value = match[0];
      fragment.className = value.startsWith('--') ? 'comment' : value.startsWith("'") ? 'literal' : 'keyword';
      fragment.textContent = value;
      content.append(line.slice(last, match.index), fragment);
      last = match.index + value.length;
    }
    content.append(line.slice(last));
    row.append(number, content);
    lines.append(row);
  }
  byId(id + '-sql').replaceChildren(lines);
}

function summary(output) {
  return 'Grade ' + output.grade + ' · ' + output.checked + ' objects checked · ' +
    output.high + (output.high === 1 ? ' high finding' : ' high findings');
}

function reveal(answer, openFix) {
  byId('decision').hidden = true;
  byId('result').hidden = false;
  byId('answer-label').textContent = answer === 'yes' ? 'Your call: it saves' :
    answer === 'no' ? 'Your call: it rolls back' : 'RattleCheck result';
  byId('fix').hidden = !openFix;
  byId('show-fix').hidden = openFix;
  byId(openFix ? 'fix-title' : 'result-title').focus();
}

function navigate() {
  if (!example) return;
  if (window.location.hash === '#fix') {
    reveal(originalAnswer, true);
  } else if (originalAnswer) {
    reveal(originalAnswer, false);
  } else {
    byId('result').hidden = true;
    byId('decision').hidden = false;
  }
}

function say(message) {
  clearTimeout(feedbackTimer);
  byId('copy-feedback').textContent = message;
  feedbackTimer = setTimeout(() => { byId('copy-feedback').textContent = ''; }, 3500);
}

async function copy(value, label) {
  byId('copy-manual').hidden = true;
  try {
    await navigator.clipboard.writeText(value);
    say(label + ' copied.');
  } catch {
    byId('copy-feedback').textContent = '';
    byId('copy-label').textContent = 'Copy the ' + label.toLowerCase();
    byId('copy-value').value = value;
    byId('copy-manual').hidden = false;
    byId('copy-value').focus();
    byId('copy-value').select();
  }
}

async function loadExample() {
  byId('load-error').hidden = true;
  byId('proposal-file').textContent = 'Loading SQL…';
  try {
    const response = await fetch('./case.json');
    if (!response.ok) throw new Error('Example unavailable');
    const fixture = await response.json();
    showCode('proposal', fixture.proposal);
    showCode('setup', fixture.setup);
    showCode('fix', fixture.fix);
    byId('finding').textContent = fixture.before.rule + ' · ' + summary(fixture.before);
    byId('fix-result').textContent = summary(fixture.after);
    byId('source').href = fixture.sourceUrl;
    const command = 'npx github:chaseakub/rattlecheck#v' + fixture.version;
    byId('command').textContent = command;
    byId('install').setAttribute('aria-label', 'Copy command: ' + command);
    byId('install').disabled = false;
    byId('setup').hidden = false;
    for (const button of document.querySelectorAll('[data-answer]')) button.disabled = false;
    example = fixture;
    navigate();
  } catch {
    byId('proposal-file').textContent = 'Example unavailable';
    byId('load-error').hidden = false;
  }
}

for (const button of document.querySelectorAll('[data-answer]')) {
  button.addEventListener('click', () => {
    originalAnswer = button.dataset.answer;
    reveal(originalAnswer, false);
  });
}
for (const button of document.querySelectorAll('[data-share]')) {
  button.addEventListener('click', () => {
    const link = new URL(window.location.href);
    link.hash = '';
    link.search = '';
    copy(link.href, 'Challenge link');
  });
}

byId('install').addEventListener('click', () => copy(byId('command').textContent, 'Command'));
byId('show-fix').addEventListener('click', (event) => {
  event.preventDefault();
  window.location.hash = 'fix';
});
byId('retry').addEventListener('click', loadExample);
window.addEventListener('hashchange', navigate);
loadExample();
