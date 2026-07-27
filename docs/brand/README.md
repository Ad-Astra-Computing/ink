# Sign in with INK button assets

The "Sign in with INK" button that a relying party puts on its sign-in screen.
It starts the flow in [`specs/ink-agent-authorization.md`](../../specs/ink-agent-authorization.md):
a click hands the sign-in to the visitor's own INK agent, which confirms the
request with them and proves their identity to the site.

- `sign-in-with-ink-dark.svg` for light backgrounds, 196 by 44
- `sign-in-with-ink-light.svg` for dark backgrounds, 196 by 44
- `ink-nib.svg` for the nib mark on its own

Drop one straight into a link:

```html
<a href="/auth/ink/start">
  <img src="sign-in-with-ink-dark.svg" alt="Sign in with INK" width="196" height="44">
</a>
```

Usage guidance, a live markup-and-CSS variant and the sizing rules are on the
canonical brand page at
<https://ink.tulpa.network/extensions/sign-in-button/>.
