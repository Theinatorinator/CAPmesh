<!--
SPDX-FileCopyrightText: 2026 Logan Mamanakis Logan.Mamanakis@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Architecture

Here are some extra docs. With mermaid diagram support.

```mermaid
graph TD
    A[Start] --> B{Is it sunny?}
    B -->|Yes| C[Go for a walk]
    B -->|No| D[Stay indoors]
    C --> E[Buy ice cream]
    D --> F[Read a book]
    E --> G[End]
    F --> G

```
