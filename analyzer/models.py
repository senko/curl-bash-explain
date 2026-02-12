import hashlib

from django.db import models


class AnalysisCache(models.Model):
    """Cache of analyzed shell scripts."""

    input_text = models.TextField(help_text="Original user input (URL or command)")
    script_url = models.URLField(max_length=2048, help_text="Resolved script download URL")
    script_hash = models.CharField(
        max_length=64, db_index=True, help_text="SHA-256 hash of the script content"
    )
    script_content = models.TextField(help_text="The downloaded script content")
    explanation_md = models.TextField(help_text="LLM-generated explanation (Markdown)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["script_url"]),
        ]

    def __str__(self):
        return f"{self.script_url} ({self.script_hash[:12]})"

    @staticmethod
    def hash_script(content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()
