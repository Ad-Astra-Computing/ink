// The modules under conformance/v1/independent/ are deliberately plain .mjs
// with no types: they must not import anything from src/, and giving them
// declarations generated from src/ would reintroduce exactly the dependency
// they exist to avoid.
//
// One ambient declaration rather than a `@ts-expect-error` per import. The
// directive form is brittle: TypeScript reports a module-resolution error on
// the specifier line, so any reformat that wraps an import onto several lines
// moves the error away from the directive and the build fails on an unused
// directive instead. Prettier does exactly that.
declare module "../conformance/v1/independent/*.mjs";
