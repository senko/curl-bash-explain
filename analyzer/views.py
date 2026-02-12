import logging

import markdown
from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods

from .models import AnalysisCache
from .services import process_input, AnalysisError

logger = logging.getLogger(__name__)


def index(request):
    return render(request, "analyzer/index.html")


@require_http_methods(["POST"])
def analyze(request):
    raw_input = request.POST.get("input", "").strip()

    if not raw_input:
        return render(request, "analyzer/index.html", {
            "error": "Please enter a URL or shell command.",
            "input_value": raw_input,
        })

    try:
        result = process_input(raw_input)
    except AnalysisError as exc:
        logger.warning("Analysis error: %s", exc)
        return render(request, "analyzer/index.html", {
            "error": str(exc),
            "input_value": raw_input,
        })
    except Exception as exc:
        logger.exception("Unexpected error during analysis")
        return render(request, "analyzer/index.html", {
            "error": f"An unexpected error occurred: {exc}",
            "input_value": raw_input,
        })

    return redirect("results", script_hash=result["script_hash"])


def results(request, script_hash):
    entry = AnalysisCache.objects.filter(script_hash=script_hash).first()
    if not entry:
        return render(request, "analyzer/index.html", {
            "error": "Analysis not found. It may have been replaced by a newer version.",
        })

    explanation_html = markdown.markdown(
        entry.explanation_md, extensions=["fenced_code", "tables"]
    )

    return render(request, "analyzer/results.html", {
        "result": {
            "script_url": entry.script_url,
            "script_content": entry.script_content,
            "explanation_html": explanation_html,
        },
        "input_value": entry.input_text,
    })
