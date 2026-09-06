# Gantry documentation website

Open [`docs/gantry/index.html`](../../docs/gantry/index.html) directly in a browser, or
serve the repository with any static web server. The page includes all
`docs/gantry/**/*.md` guides and release notes, styling, highlighted examples,
icons, and section search. It makes no external requests until a reader opens
an external link. The product showcase links to the manual using relative URLs.

The generated page supports deep links such as
`index.html#networking/define-an-egress-policy`, browser back/forward navigation,
keyboard search (`Ctrl+K`, `Cmd+K`, or `/`), dark/light themes, a responsive
sidebar, and an on-page outline. Without JavaScript, every guide remains
readable and internal links work as ordinary document anchors.

## Update the website

Markdown remains the source of truth. Do not edit `docs/gantry/index.html`
directly. Change a guide or [`template.html`](template.html), then run
from the repository root:

```sh
uv run scripts/build_docs.py
```

The script declares its pinned Markdown and syntax-highlighting dependencies
inline; `uv` installs them in an isolated cache. No Node, framework, bundler,
or build dependencies are required by readers.

Check the generated artifact and run the generator regression tests:

```sh
uv run scripts/build_docs.py --check
uv run scripts/build_docs.py --test
```

Commit the Markdown/template changes and regenerated HTML together. New guides
are automatically included; set their preferred group, label, and order in
`GROUPS` in `scripts/build_docs.py`. Release notes are discovered and ordered
newest first. The generator fails for broken links to bundled headings rather
than publishing an invalid local link.

## Publish with GitHub Pages

The repository's [GitHub Pages workflow](../../.github/workflows/pages.yml)
builds and deploys the showcase and manual together:

- Showcase: <https://ejpir.github.io/gantry/>
- Manual: <https://ejpir.github.io/gantry/docs/gantry/>

One-time setup by a repository administrator:

1. Open [Settings → Pages](https://github.com/ejpir/gantry/settings/pages).
2. Under **Build and deployment**, set **Source** to **GitHub Actions**.
3. Merge the website files, generator, template, and workflow into `main`.
   The Pages workflow runs automatically. If the files are already on `main`,
   run **Actions → GitHub Pages → Run workflow** on `main`.

If the `github-pages` environment has protection rules, permit deployments
from `main` and approve the deployment when requested.

Future pushes to `main` that change the website, manual, or generator rebuild
and publish automatically. Pull requests run the build and generator tests,
but cannot deploy; manual runs on feature branches are also build-only.

CI regenerates the manual from the committed Markdown before uploading, so the
published docs do not depend on a potentially stale generated HTML file. Only
`index.html`, `docs/gantry/index.html`, and a `.nojekyll` marker enter the Pages
artifact. Repository sources, credentials, VM images, and other local artifacts
are not published. Relative URLs work under GitHub's `/gantry/` project prefix;
there is no Jekyll configuration, application server, or custom domain required.

## Rendering details

- Relative links between bundled guides stay within the manual. References to
  other repository files open their GitHub source in a new tab.
- Raw Markdown HTML is escaped. Local Markdown images are embedded; remote
  images fail the build to preserve offline operation.
- Examples are syntax-highlighted without changing their text. **Copy** copies
  the complete displayed example, including any shell prompts and sample
  output; it never runs commands.
- ASCII diagrams preserve their spacing and scroll horizontally on small
  screens. Mermaid fences retain their source and link explicitly to GitHub's
  rendered diagram, rather than loading a remote renderer.
- Search is local to the browser. The theme preference is the only persisted
  browser setting; storage-denied environments still work.
