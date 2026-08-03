# Get data from IPAWS CAP feed and cache it
# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Use APScheduler to schedule poll tasks, using httpx
# Parse CAP messages with cap-tools
# Cache data using SQLite and SQLmodel
# Clear old data from the cache using APScheduler-expiration in the CAP message
