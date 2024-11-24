# Go secrets

[![Go](https://github.com/noj/secrets/actions/workflows/go.yaml/badge.svg)](https://github.com/noj/secrets/actions/workflows/go.yaml)

Super simple zero-dependencies secrets support lib, designed to be used in a k8s setting with
secrets mounted as files in the pods.

The main goal is to avoid accidentally logging a secret and also making it grep'able for easy auditing.
