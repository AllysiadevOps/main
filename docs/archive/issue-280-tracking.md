# Historical Archive: Issue #280 Tracking Note

> **Historical Archive**: This document is an unmaintained historical tracking note preserved for reference. It is not part of the active protocol documentation.

---

# Issue #280 tracking note

This pull request tracks proof-cache invalidation after registration for
[#280](https://github.com/harpocrates-stellar/main/issues/280).

The repository already provides a bounded verifier cache with explicit
single-entry and full-cache invalidation methods. Registration integration
should call that canonical invalidation boundary after a successful state
change, preserving privacy-safe cache keys and avoiding duplicate cache logic.
