# Editor setup

Open a Linux-filesystem checkout through WSL or a Linux remote session. Select its
`.venv/bin/python` interpreter after `uv sync --locked`. Use an integrated Linux
terminal for CLI entry points. Shell wrappers require executable permissions; if
an archive extraction tool removes them, use `chmod +x scripts/cyber-*`.

Open private workspace data separately with the appropriate access controls. Avoid
adding private folders to shared editor configuration, search indexes or published
project files. No personal paths, extension inventory or machine setup history are
included in the product configuration.
