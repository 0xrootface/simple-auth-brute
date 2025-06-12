# Simple Auth Brute

[![Go Reference](https://pkg.go.dev/badge/github.com/0xrootface/simple-auth-brute.svg)](https://pkg.go.dev/github.com/0xrootface/simple-auth-brute)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A straightforward and efficient Go-based command-line tool for brute-forcing HTTP Basic Authentication endpoints. It supports various combinations of usernames and passwords, including single values and list files, with concurrent request handling.

## ✨ Features

* **HTTP Basic Authentication Brute-Force:** Designed specifically for `Authorization: Basic` headers.
* **Flexible Input:** Supports:
    * Single username with a list of passwords.
    * List of usernames with a single password.
    * Single username with a single password.
    * Lists of usernames and passwords (all combinations).
* **Concurrent Requests:** Utilizes Go's goroutines for faster processing.
* **Customizable Concurrency:** Control the number of parallel requests.
* **Intelligent Response Handling:**
    * Highlights successful 2xx responses in **green**.
    * Silently ignores 4xx/401 (Unauthorized) responses.
    * Alerts for 5xx (Server Error) responses in **red**, suggesting potential server issues or IP bans.
* **Detailed HTTP Headers:** Sends a comprehensive set of headers to mimic common browser requests.

## 🚀 Installation

Ensure you have Go (version 1.22 or higher recommended) installed and configured correctly. Your `$PATH` and `$GOBIN` environment variables should be set.

```bash
# Set GOBIN (if not already set in your .bashrc/.zshrc)
export GOBIN="/usr/local/bin" # Or any directory in your $PATH
# export PATH="$PATH:$GOBIN" # Ensure GOBIN is in your PATH

# Install the tool
go install [github.com/0xrootface/simple-auth-brute@latest](https://github.com/0xrootface/simple-auth-brute@latest)
