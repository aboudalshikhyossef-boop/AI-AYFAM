# AI AYFAM — UI navigation structure

The desktop navigation contains exactly seven primary workspaces:

1. **غرفة العمليات** — dashboard and current posture.
2. **الفحوصات الأمنية** — scan setup plus the existing audit/tool catalogue.
3. **النتائج والتحليل** — findings, incident timeline, correlated attack chains, and report review.
4. **المراقبة والحماية** — Sentinel event history and connected USB/storage controls.
5. **المساعد والمعرفة** — chat, local knowledge library, and playbook generation.
6. **تدريب نموذج AYFAM** — local corpus preparation and from-scratch model training.
7. **الإعدادات** — application and provider configuration.

Related screens are selected inside their workspace, rather than taking a permanent slot in the primary navigation. Existing internal page keys remain supported so shortcuts, buttons, and established behavior keep working.

This change consolidates navigation; it does not remove security engines, data, user corpora, checkpoints, or test coverage. Potentially destructive security actions remain behind their existing explicit controls and permission checks.
