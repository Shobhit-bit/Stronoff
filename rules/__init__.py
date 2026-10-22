"""vulnscan rule engine (Phase 2). Pure and offline: collector JSON in, findings out."""
ENGINE_VERSION = "0.1"
MIN_COLLECTOR_VERSION = "1.2"   # older collector output is treated as UNKNOWN (known-buggy facts)
