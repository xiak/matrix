# Audit service

Audit is the PaaS unified audit authority. Existing implementation will be
adopted from the Senatria source repository through a fixed-commit,
minimal-dependency review.

PaaS may keep local operation evidence, but it must publish the minimal unified
audit envelope through a transactional outbox and must not create a second
audit query or retention authority.
