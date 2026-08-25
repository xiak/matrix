# IAM service

IAM is the PaaS identity and authorization authority. Existing implementation
will be adopted from the Senatria source repository through a fixed-commit,
minimal-dependency review.

PaaS must use IAM contracts and SDKs. It must not create parallel user,
session, role, grant, or permission-decision authorities.
