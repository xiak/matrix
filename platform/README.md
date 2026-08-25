# Platform foundations and SDKs

This directory contains intentionally public code shared by multiple PaaS
services. Initial candidates are the Go foundation, IAM client credentials and
permission client, Audit HTTP client, and Audit SQL outbox.

Code is admitted here only when it has multiple concrete consumers and a
stable contract. Service-specific domain logic stays with its owning service.
