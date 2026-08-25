# PaaS console

The PaaS console will use Next.js 16, React 19, strict TypeScript, and an
independently owned design system. Framework-neutral Xiak components may be
selectively adopted after provenance, dependency, accessibility, and visual
acceptance checks.

The console consumes `/api/paas/v1/*` through APISIX. It never calls the APISIX
Admin API or infers authorization from role names.
