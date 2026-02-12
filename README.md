# curl | bash > explain

A web app that analyzes `curl | bash` installer scripts so you can understand what they do _before_ you run them. Paste a command like `curl -fsSL https://example.com/install.sh | bash` or a project URL, and get an AI-powered, plain-English breakdown of the script's behavior, permissions, network activity, and potential risks.

Built with Django and the OpenAI API.

## How it works

1. **Parse input** — accepts a `curl`/`wget` pipe-to-bash command or a plain URL. For URLs, it scrapes the page to find an installer command.
2. **Download** — fetches the shell script without executing it (max 512 KB).
3. **Analyze** — sends the script to an LLM for a structured security review (overview, step-by-step breakdown, what it installs, network activity, privilege escalation, concerns, and a verdict).
4. **Cache** — results are cached by script URL + content hash, so repeat lookups are instant.

## Local setup

Requires [uv](https://docs.astral.sh/uv/) and Python 3.12+.

```bash
# Clone the repo
git clone <repo-url> && cd curlbash

# Install dependencies
uv sync

# Configure environment
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY

# Run migrations
uv run python manage.py migrate

# Start the dev server
uv run python manage.py runserver
```

The app will be available at [http://localhost:8000](http://localhost:8000).

### Environment variables

| Variable | Description | Default |
|---|---|---|
| `DEBUG` | Enable Django debug mode | `false` |
| `DATABASE_URL` | Database connection string | `sqlite:///db.sqlite3` |
| `OPENAI_API_KEY` | OpenAI API key (required) | — |
| `OPENAI_MODEL` | Model to use for analysis | `gpt-5.3` |

## Production

The included `curlbash.service` systemd unit runs the app with Gunicorn:

```bash
uv run gunicorn curlbash_project.wsgi:application --bind 0.0.0.0:8000
```
