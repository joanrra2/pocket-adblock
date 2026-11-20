"""Renders the project site's pages in every language.

Templates (site/pages/*.html, installer/index.html) hold the layout with
{{t:key}} for text; site/i18n/<lang>.json holds the text, HTML allowed. English
is the default, at the site root; other languages live under /<lang>/.
Placeholders after the text is in: {{root}} (path to the site root), {{base}}
(to this language's home), {{lang}}, {{REPO}}, plus the language menu,
the hreflang links and the first-visit language pick.

Every language must have exactly the keys English has, and nothing may be left
unfilled: the build fails otherwise, so a missing translation can't ship.
"""
import html
import json
import os
import re

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
LANGS = ['en', 'es', 'fr', 'it']  # the first is the default, served at the root
PAGES = [  # template -> output path inside a language's folder
    (os.path.join('site', 'pages', 'index.html'), 'index.html'),
    (os.path.join('site', 'pages', 'guide.html'), 'guide.html'),
    (os.path.join('installer', 'index.html'), os.path.join('install', 'index.html')),
]
KEY = re.compile(r'\{\{t:([a-z0-9_.]+)\}\}')
LEFT = re.compile(r'\{\{[^}]*\}\}')


def load_strings():
    strings = {}
    for lang in LANGS:
        with open(os.path.join(ROOT, 'site', 'i18n', lang + '.json'), encoding='utf-8') as f:
            strings[lang] = json.load(f)
    ref = set(strings[LANGS[0]])
    for lang in LANGS[1:]:
        keys = set(strings[lang])
        if keys != ref:
            raise SystemExit(f'site/i18n/{lang}.json: missing {sorted(ref - keys)}, extra {sorted(keys - ref)}')
    return strings


def prefix(lang):
    return '' if lang == LANGS[0] else lang + '/'


def page_url(rel):
    """The URL form of an output path: install/index.html -> install/, index.html -> ''."""
    rel = rel.replace(os.sep, '/')
    return rel[:-len('index.html')] if rel.endswith('index.html') else rel


def lang_menu(strings, lang, root, rel):
    items = []
    for other in LANGS:
        href = root + prefix(other) + page_url(rel) or './'
        cur = ' aria-current="true"' if other == lang else ''
        name = html.escape(strings[other]['lang.name'])
        items.append(f'<li><a href="{href}" hreflang="{other}" lang="{other}" data-lang="{other}"{cur}>{name}</a></li>')
    label = html.escape(strings[lang]['lang.menu'])
    globe = ('<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
             'aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"/></svg>')
    return (f'<details class="lang"><summary aria-label="{label}">{globe}{lang.upper()}</summary>'
            f'<ul>{"".join(items)}</ul></details>')


def alternates(site_url, rel):
    if not site_url:
        return ''
    links = [f'<link rel="alternate" hreflang="{lang}" href="{site_url}{prefix(lang)}{page_url(rel)}">' for lang in LANGS]
    links.append(f'<link rel="alternate" hreflang="x-default" href="{site_url}{page_url(rel)}">')
    return '\n'.join(links)


def lang_pick(lang, root, rel):
    """Remembers the visitor's choice; on the default language's pages, a first
    visit from a browser set to another language goes to that language."""
    targets = {other: root + prefix(other) + page_url(rel) for other in LANGS[1:]}
    return ('<script>(function(){var L=' + json.dumps(lang) + ',K="site-lang",T=' + json.dumps(targets) + ';'
            'function g(){try{return localStorage.getItem(K)}catch(e){return null}}'
            'document.addEventListener("click",function(e){var a=e.target.closest&&e.target.closest("a[data-lang]");'
            'if(a){try{localStorage.setItem(K,a.dataset.lang)}catch(x){}}});'
            'if(L!=' + json.dumps(LANGS[0]) + '||g())return;'
            'var w=navigator.languages||[navigator.language||""];'
            'for(var i=0;i<w.length;i++){var c=String(w[i]).slice(0,2).toLowerCase();'
            'if(c==' + json.dumps(LANGS[0]) + ')return;if(T[c]){location.replace(T[c]+location.hash);return}}'
            '})();</script>')


def render(template, strings, lang, rel, repo, site_url):
    depth = rel.replace(os.sep, '/').count('/') + (0 if lang == LANGS[0] else 1)
    root = '../' * depth
    base = '../' if rel.replace(os.sep, '/').count('/') else './'

    def text(m):
        key = m.group(1)
        if key not in strings[lang]:
            raise SystemExit(f'{lang}: no text for {key}')
        return strings[lang][key]

    page = KEY.sub(text, template)
    values = {
        'lang': lang, 'root': root, 'base': base, 'REPO': repo,
        'langmenu': lang_menu(strings, lang, root, rel),
        'alternates': alternates(site_url, rel),
        'langpick': lang_pick(lang, root, rel),
    }
    for name, value in values.items():
        page = page.replace('{{' + name + '}}', value)
    left = LEFT.findall(page)
    if left:
        raise SystemExit(f'{lang}/{rel}: unfilled {sorted(set(left))}')
    return page


def site_url_for(repo):
    """https://github.com/<owner>/<name> -> https://<owner>.github.io/<name>/ ('' otherwise)."""
    m = re.match(r'https://github\.com/([^/]+)/([^/]+?)/?$', repo)
    return f'https://{m.group(1).lower()}.github.io/{m.group(2)}/' if m else ''


def build(out, repo):
    strings = load_strings()
    site_url = site_url_for(repo)
    for src, rel in PAGES:
        with open(os.path.join(ROOT, src), encoding='utf-8') as f:
            template = f.read()
        for lang in LANGS:
            dest = os.path.join(out, prefix(lang), rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)  # NOSONAR - developer tool: the output folder is a command-line argument
            with open(dest, 'w', encoding='utf-8') as f:  # NOSONAR - as above
                f.write(render(template, strings, lang, rel, repo, site_url))
