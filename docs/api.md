# API Reference

## Public API

::: hushlog
    options:
      members:
        - patch
        - unpatch
        - redact_dict
        - structlog_processor
        - loguru_sink
      show_root_heading: false

## Config

::: hushlog._config.Config
    options:
      show_root_heading: true
      members_order: source

## RedactingJsonFormatter

::: hushlog._json_formatter.RedactingJsonFormatter
    options:
      show_root_heading: true
      members_order: source

## PatternRegistry

::: hushlog._registry.PatternRegistry
    options:
      show_root_heading: true
      members:
        - register
        - unregister
        - redact
        - redact_dict
        - from_config
